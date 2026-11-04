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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	cfg          *config.Config
	minter       Minter
	exchanger    Exchanger
	fetchTimeout time.Duration
	now          func() time.Time
}

// NewServer returns a Server for cfg. A fetchTimeout of zero means
// DefaultFetchTimeout.
func NewServer(cfg *config.Config, minter Minter, exchanger Exchanger, fetchTimeout time.Duration) *Server {
	if fetchTimeout <= 0 {
		fetchTimeout = DefaultFetchTimeout
	}
	return &Server{
		cfg:          cfg,
		minter:       minter,
		exchanger:    exchanger,
		fetchTimeout: fetchTimeout,
		now:          time.Now,
	}
}

// FetchSecret returns the access token for the profile named in the URI,
// issued to the requesting actor.
func (s *Server) FetchSecret(ctx context.Context, req *credprovider.FetchSecretRequest) (*credprovider.FetchSecretResponse, error) {
	start := s.now()
	profileName, err := s.parseURI(req.GetUri())
	var tok string
	if err == nil {
		tok, err = s.fetch(ctx, req.GetActorSpiffeId(), profileName)
	}
	attrs := []any{
		slog.String("actor", req.GetActorSpiffeId()),
		slog.String("profile", profileName),
		slog.String("outcome", status.Code(err).String()),
		slog.Duration("latency", s.now().Sub(start)),
	}
	if err != nil {
		slog.WarnContext(ctx, "token exchange failed", append(attrs, slog.String("err", status.Convert(err).Message()))...)
		return nil, err
	}
	slog.InfoContext(ctx, "token exchange", attrs...)
	return &credprovider.FetchSecretResponse{OpaqueBytes: []byte(tok)}, nil
}

// fetch authorizes the request, mints the actor's JWT and exchanges it.
func (s *Server) fetch(ctx context.Context, actorID, profileName string) (string, error) {
	atespace, name, err := parseActorSPIFFEID(actorID)
	if err != nil {
		return "", status.Errorf(codes.PermissionDenied, "invalid actor SPIFFE ID: %v", err)
	}
	if !s.cfg.Allowed(atespace, profileName) {
		return "", status.Errorf(codes.PermissionDenied, "atespace %q is not granted profile %q", atespace, profileName)
	}
	profile, ok := s.cfg.Profile(profileName)
	if !ok {
		return "", status.Errorf(codes.Internal, "granted profile %q is not configured", profileName)
	}
	ctx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
	defer cancel()
	t, err := s.exchange(ctx, atespace, name, profile)
	if err != nil {
		return "", err
	}
	return t.AccessToken, nil
}

func (s *Server) exchange(ctx context.Context, atespace, name string, p *config.Profile) (tokenexchange.Token, error) {
	jwt, err := s.minter.MintActorJWT(ctx, atespace, name, p.Audience)
	if err != nil {
		return tokenexchange.Token{}, err
	}
	return s.exchanger.Exchange(ctx, p.TokenURL, jwt, p.Audience, p.Scopes)
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
