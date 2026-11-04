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
	uriScheme            = "ate-secret"
	tokenExchangePrefix  = "/token-exchange/"
	actorTrustDomain     = "substrate-actor.local"
	actorJWTLifetimeSecs = 300

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
// codes.
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
}

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
	switch {
	case err != nil:
		slog.WarnContext(ctx, "token exchange failed", append(attrs, slog.String("err", status.Convert(err).Message()))...)
		return nil, err
	case source == "miss":
		slog.InfoContext(ctx, "token exchange", attrs...)
	default:
		slog.DebugContext(ctx, "token exchange", attrs...)
	}
	return &credprovider.FetchSecretResponse{OpaqueBytes: []byte(tok)}, nil
}

// fetch authorizes the request and returns a token and where it came from:
// the cache ("hit"), a new exchange ("miss"), one already in flight
// ("shared"), or none because the caller gave up ("abandoned").
func (s *Server) fetch(ctx context.Context, actorID, profileName string) (string, string, error) {
	atespace, name, err := parseActorSPIFFEID(actorID)
	if err != nil {
		return "", "", status.Errorf(codes.PermissionDenied, "invalid actor SPIFFE ID: %v", err)
	}
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

	ch := s.group.DoChan(key.String(), func() (any, error) {
		if tok, ok := s.cached(key); ok {
			return tok, nil
		}
		fctx, cancel := context.WithTimeout(s.ctx, s.fetchTimeout)
		defer cancel()
		t, err := s.exchange(fctx, atespace, name, profile)
		if err != nil {
			return nil, err
		}
		s.store(key, t)
		return t.AccessToken, nil
	})
	select {
	case <-ctx.Done():
		return "", "abandoned", status.FromContextError(ctx.Err()).Err()
	case r := <-ch:
		source := "miss"
		if r.Shared {
			source = "shared"
		}
		if r.Err != nil {
			return "", source, r.Err
		}
		return r.Val.(string), source, nil
	}
}

func (s *Server) exchange(ctx context.Context, atespace, name string, p *config.Profile) (tokenexchange.Token, error) {
	jwt, err := s.minter.MintActorJWT(ctx, atespace, name, p.SubjectTokenAudience)
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

// store caches t for reuseFor(t), if that is positive.
func (s *Server) store(key cacheKey, t tokenexchange.Token) {
	if reuse := reuseFor(t); reuse > 0 {
		s.tokens.Set(key, t.AccessToken, reuse)
	}
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
