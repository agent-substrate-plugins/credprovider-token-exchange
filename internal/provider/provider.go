// Copyright 2026 The Agent Substrate Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package provider implements substrate's CredentialProvider API by exchanging
// an actor's Substrate-minted JWT for an access token at an RFC 8693 token
// endpoint, for URIs of the form
//
//	ate-secret://<providerName>/token-exchange/<profile>
package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/util/validation"

	ateapi "go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/api/credprovider/v1"

	"plugins.go.ate.dev/credprovider-token-exchange/internal/config"
	"plugins.go.ate.dev/credprovider-token-exchange/internal/tokenexchange"
)

const (
	uriScheme           = "ate-secret"
	tokenExchangePrefix = "/token-exchange/"
	actorTrustDomain    = "substrate-actor.local"

	// actorJWTLifetimeSecs is the most MintActorJwt accepts. Google Cloud STS
	// ends the federated token when the subject JWT expires, so the JWT
	// lifetime bounds how long the exchanged token can be cached.
	actorJWTLifetimeSecs = 3600

	// DefaultFetchTimeout leaves headroom under the egress gateway's 4s
	// credential injection timeout.
	DefaultFetchTimeout = 3 * time.Second

	// minReuseMargin is the least lifetime left at which a token stops being
	// reused.
	minReuseMargin = 30 * time.Second
	// unknownExpiryReuse is how long a token without expires_in is reused.
	unknownExpiryReuse = 60 * time.Second
	// maxReuse bounds how long a token is served from the cache.
	maxReuse = time.Hour
)

// Minter mints an actor JWT bound to audience.
type Minter interface {
	MintActorJWT(ctx context.Context, atespace, name, audience string) (string, error)
}

// Exchanger turns a subject token into an access token.
type Exchanger interface {
	Exchange(ctx context.Context, tokenURL, subjectToken, audience string, scopes []string) (tokenexchange.Token, error)
}

// ControlMinter mints through ate-api-server's Control service.
type ControlMinter struct {
	Client ateapi.ControlClient
}

// MintActorJWT calls Control.MintActorJwt, mapping its errors to FetchSecret
// codes: NotFound to PermissionDenied; Unavailable, DeadlineExceeded and
// Canceled kept; ResourceExhausted and Aborted, which a retry can get past, to
// Unavailable; anything else to FailedPrecondition. The gateway answers
// PermissionDenied and FailedPrecondition with 403, and Unavailable and
// DeadlineExceeded with a retryable 503.
func (m ControlMinter) MintActorJWT(ctx context.Context, atespace, name, audience string) (string, error) {
	resp, err := m.Client.MintActorJwt(ctx, &ateapi.MintActorJwtRequest{
		Actor:             &ateapi.ObjectRef{Atespace: atespace, Name: name},
		Audiences:         []string{audience},
		ExpirationSeconds: actorJWTLifetimeSecs,
	})
	if err != nil {
		st := status.Convert(err)
		switch st.Code() {
		case codes.NotFound:
			return "", status.Errorf(codes.PermissionDenied, "MintActorJwt: actor not found: %s", st.Message())
		case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
			return "", status.Errorf(st.Code(), "MintActorJwt: %s", st.Message())
		case codes.ResourceExhausted, codes.Aborted:
			return "", status.Errorf(codes.Unavailable, "MintActorJwt: %s: %s", st.Code(), st.Message())
		default:
			return "", status.Errorf(codes.FailedPrecondition, "MintActorJwt: %s: %s", st.Code(), st.Message())
		}
	}
	if resp.GetActorJwt() == "" {
		return "", status.Error(codes.FailedPrecondition, "MintActorJwt returned an empty token")
	}
	return resp.GetActorJwt(), nil
}

// Server implements credprovider.CredentialProviderServer.
type Server struct {
	credprovider.UnimplementedCredentialProviderServer

	ctx          context.Context
	cfg          *config.Config
	minter       Minter
	exchanger    Exchanger
	fetchTimeout time.Duration

	// tokens maps a cacheKey to an access token until it stops being reused.
	tokens *cache.Expiring
	// group collapses concurrent exchanges of one token into a single call.
	group singleflight.Group

	log *slog.Logger
}

// cacheKey names a cached token. It holds no actor UID because
// FetchSecretRequest carries none, only the actor's SPIFFE ID, so an actor
// deleted and recreated under the same name can get its predecessor's token
// until that token stops being reused.
type cacheKey struct{ atespace, name, profile string }

func (k cacheKey) String() string { return k.atespace + "/" + k.name + "/" + k.profile }

// NewServer returns a Server for cfg. Exchanges run under ctx, not the
// caller's, so a caller giving up doesn't abort one that others share; cancel
// ctx on shutdown. A fetchTimeout of zero means DefaultFetchTimeout.
func NewServer(ctx context.Context, cfg *config.Config, minter Minter, exchanger Exchanger, fetchTimeout time.Duration) *Server {
	if fetchTimeout <= 0 {
		fetchTimeout = DefaultFetchTimeout
	}
	return &Server{
		ctx:          ctx,
		cfg:          cfg,
		minter:       minter,
		exchanger:    exchanger,
		fetchTimeout: fetchTimeout,
		tokens:       cache.NewExpiring(),
		log:          slog.Default(),
	}
}

// FetchSecret returns the access token for the profile named in the URI,
// issued to the requesting actor.
func (s *Server) FetchSecret(ctx context.Context, req *credprovider.FetchSecretRequest) (*credprovider.FetchSecretResponse, error) {
	start := time.Now()
	profileName, err := s.parseURI(req.GetUri())
	source := ""
	var tok string
	if err == nil {
		tok, source, err = s.fetch(ctx, req.GetActorSpiffeId(), profileName)
	}
	attrs := []any{
		slog.String("actor", req.GetActorSpiffeId()),
		slog.String("profile", profileName),
		slog.String("cache", source),
		slog.String("outcome", status.Code(err).String()),
		slog.Duration("latency", time.Since(start)),
	}
	// Each exchange is logged once, by the flight that ran it (runFlight), at
	// Info, or Warn if it failed. A request that got its outcome from a flight
	// or the cache is logged here only at Debug. One that failed before
	// reaching a flight, or gave up waiting for one, is logged at Warn.
	switch {
	case err != nil && (source == "" || source == "abandoned"):
		s.log.WarnContext(ctx, "fetch secret failed", append(attrs, slog.String("err", status.Convert(err).Message()))...)
	case err != nil:
		s.log.DebugContext(ctx, "fetch secret failed", append(attrs, slog.String("err", status.Convert(err).Message()))...)
	default:
		s.log.DebugContext(ctx, "fetch secret", attrs...)
	}
	if err != nil {
		return nil, err
	}
	return &credprovider.FetchSecretResponse{OpaqueBytes: []byte(tok)}, nil
}

// flight is the result of one exchange flight.
type flight struct {
	token string
	// exchanged is false when the flight found the token already cached, by
	// a flight that finished after the caller looked.
	exchanged bool
}

// fetch authorizes the request and returns a token and where it came from:
// the cache ("hit"), an exchange this call ran ("miss"), an exchange another
// call ran ("shared"), or none because the caller gave up ("abandoned").
func (s *Server) fetch(ctx context.Context, actorID, profileName string) (string, string, error) {
	atespace, name, err := parseActorSPIFFEID(actorID)
	if err != nil {
		return "", "", status.Errorf(codes.PermissionDenied, "invalid actor SPIFFE ID: %v", err)
	}
	// The policy check stays ahead of the cache lookup, so a cached token is
	// never served to an atespace the policy doesn't grant it.
	if !s.cfg.Allowed(atespace, profileName) {
		return "", "", status.Errorf(codes.PermissionDenied, "atespace %q is not granted profile %q", atespace, profileName)
	}
	profile, ok := s.cfg.Profile(profileName)
	if !ok {
		return "", "", status.Errorf(codes.Internal, "granted profile %q is not configured", profileName)
	}

	key := cacheKey{atespace, name, profileName}
	if tok, ok := s.cached(key); ok {
		return tok, "hit", nil
	}

	// Only the call that starts the flight runs this function, so led tells
	// it apart from calls that join. singleflight's Result.Shared can't: once
	// any call joins, it is true for the starter too. led is read only after
	// the result arrives on ch, which is sent after the function returns.
	led := false
	ch := s.group.DoChan(key.String(), func() (any, error) {
		led = true
		f, err := s.runFlight(key, actorID, profile)
		return f, err
	})
	select {
	case <-ctx.Done():
		return "", "abandoned", status.FromContextError(ctx.Err()).Err()
	case r := <-ch:
		source := "shared"
		if led {
			source = "miss"
		}
		if r.Err != nil {
			return "", source, r.Err
		}
		f := r.Val.(flight)
		if led && !f.exchanged {
			source = "hit"
		}
		return f.token, source, nil
	}
}

// runFlight returns key's token from the cache, if a flight that finished
// after the caller looked filled it, or else from a new exchange under the
// server context, which it caches. It logs each exchange, and since it runs
// to the end even when every caller has given up, its line is the only record
// of an exchange nobody waited for.
func (s *Server) runFlight(key cacheKey, actorID string, p *config.Profile) (flight, error) {
	if tok, ok := s.cached(key); ok {
		return flight{token: tok}, nil
	}
	start := time.Now()
	fctx, cancel := context.WithTimeout(s.ctx, s.fetchTimeout)
	defer cancel()
	t, err := s.exchange(fctx, key.atespace, key.name, p)
	attrs := []any{
		slog.String("actor", actorID),
		slog.String("profile", p.Name),
		slog.String("outcome", status.Code(err).String()),
		slog.Duration("latency", time.Since(start)),
	}
	if err != nil {
		s.log.WarnContext(fctx, "token exchange failed", append(attrs, slog.String("err", status.Convert(err).Message()))...)
		return flight{}, err
	}
	reuse := s.store(key, t)
	s.log.InfoContext(fctx, "token exchange", append(attrs, slog.Duration("cachedFor", reuse))...)
	return flight{token: t.AccessToken, exchanged: true}, nil
}

func (s *Server) exchange(ctx context.Context, atespace, name string, p *config.Profile) (tokenexchange.Token, error) {
	jwt, err := s.minter.MintActorJWT(ctx, atespace, name, p.Audience)
	if err != nil {
		return tokenexchange.Token{}, err
	}
	return s.exchanger.Exchange(ctx, p.TokenURL, jwt, p.Audience, p.Scopes)
}

func (s *Server) cached(key cacheKey) (string, bool) {
	v, ok := s.tokens.Get(key)
	tok, _ := v.(string)
	return tok, ok
}

// store caches t for reuseFor(t), if that is positive, and returns how long
// it cached t, or 0.
func (s *Server) store(key cacheKey, t tokenexchange.Token) time.Duration {
	reuse := reuseFor(t)
	if reuse <= 0 {
		return 0
	}
	s.tokens.Set(key, t.AccessToken, reuse)
	return reuse
}

// reuseFor is how long token is served from the cache: until a third of its
// lifetime, or 30 seconds, remains, whichever comes first, and at most
// maxReuse.
func reuseFor(token tokenexchange.Token) time.Duration {
	if token.ExpiresAt.IsZero() {
		return unknownExpiryReuse
	}
	lifetime := time.Until(token.ExpiresAt)
	return min(lifetime-max(lifetime/3, minReuseMargin), maxReuse)
}

// parseURI returns the profile named by an
// ate-secret://<providerName>/token-exchange/<profile> URI.
func (s *Server) parseURI(raw string) (string, error) {
	invalid := status.Errorf(codes.InvalidArgument, "URI %q must have the form %s://%s%s<profile>", raw, uriScheme, s.cfg.ProviderName, tokenExchangePrefix)
	if strings.ContainsAny(raw, "?#%") {
		return "", invalid
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != uriScheme || u.Host != s.cfg.ProviderName || u.User != nil || u.Opaque != "" {
		return "", invalid
	}
	profile, ok := strings.CutPrefix(u.Path, tokenExchangePrefix)
	if !ok || len(validation.IsDNS1123Label(profile)) != 0 {
		return "", invalid
	}
	return profile, nil
}

// parseActorSPIFFEID parses spiffe://substrate-actor.local/actor/<atespace>/<name>.
func parseActorSPIFFEID(id string) (atespace, name string, err error) {
	invalid := fmt.Errorf("%q does not have the form spiffe://%s/actor/<atespace>/<name>", id, actorTrustDomain)
	if strings.ContainsAny(id, "?#%") {
		return "", "", invalid
	}
	u, err := url.Parse(id)
	if err != nil {
		return "", "", errors.Join(invalid, err)
	}
	if u.Scheme != "spiffe" || u.Host != actorTrustDomain || u.User != nil || u.Opaque != "" {
		return "", "", invalid
	}
	seg := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(seg) != 3 || seg[0] != "actor" || len(validation.IsDNS1123Label(seg[1])) != 0 || len(validation.IsDNS1123Label(seg[2])) != 0 {
		return "", "", invalid
	}
	return seg[1], seg[2], nil
}
