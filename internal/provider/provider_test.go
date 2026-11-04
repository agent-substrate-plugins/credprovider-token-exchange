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

package provider

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	ateapi "go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/api/credprovider/v1"

	"plugins.go.ate.dev/credprovider-token-exchange/internal/config"
	"plugins.go.ate.dev/credprovider-token-exchange/internal/tokenexchange"
)

const (
	actorID  = "spiffe://substrate-actor.local/actor/team-a/agent-1"
	audience = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q"
	apiURI   = "ate-secret://sts/token-exchange/api"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`
providerName: sts
profiles:
- name: api
  tokenUrl: https://sts.googleapis.com/v1/token
  audience: ` + audience + `
  scopes: ["read"]
- name: other
  tokenUrl: https://sts.googleapis.com/v1/token
  audience: ` + audience + `
  scopes: ["read"]
policy:
  atespaces:
    team-a: ["api"]
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newServer(t *testing.T, m Minter, e Exchanger) *Server {
	t.Helper()
	return NewServer(testConfig(t), m, e, 0)
}

func TestParseURI(t *testing.T) {
	s := newServer(t, nil, nil)
	if got, err := s.parseURI(apiURI); err != nil || got != "api" {
		t.Errorf("parseURI(%q) = %q, %v; want api", apiURI, got, err)
	}
	for _, uri := range []string{
		"",
		"ate-secret://k8s.io/token-exchange/api",
		"https://sts/token-exchange/api",
		"ate-secret://sts/token-exchange/",
		"ate-secret://sts/token-exchange/api/extra",
		"ate-secret://sts/other/api",
		"ate-secret://sts/token-exchange/api?x=1",
		"ate-secret://sts/token-exchange/api?",
		"ate-secret://sts/token-exchange/api#f",
		"ate-secret://sts/token-exchange/api#",
		"ate-secret://u@sts/token-exchange/api",
		"ate-secret://sts:443/token-exchange/api",
		"ate-secret://sts/token-exchange/%61pi",
	} {
		if _, err := s.parseURI(uri); status.Code(err) != codes.InvalidArgument {
			t.Errorf("parseURI(%q) error = %v, want InvalidArgument", uri, err)
		}
	}
}

func TestParseActorSPIFFEID(t *testing.T) {
	if a, n, err := parseActorSPIFFEID(actorID); err != nil || a != "team-a" || n != "agent-1" {
		t.Errorf("parseActorSPIFFEID(%q) = %q, %q, %v", actorID, a, n, err)
	}
	for _, id := range []string{
		"",
		"spiffe://cluster.local/actor/team-a/agent-1",
		"spiffe://substrate-actor.local/worker-for-actor/team-a/agent-1",
		"spiffe://substrate-actor.local/actor/team-a",
		"spiffe://substrate-actor.local/actor/team-a/agent-1/x",
		"spiffe://substrate-actor.local/actor/Team_A/agent-1",
		"spiffe://substrate-actor.local/actor/team-a/..",
		"spiffe://substrate-actor.local/actor/team-a/agent-1?",
		"spiffe://substrate-actor.local/actor/team-a/agent-1#",
		"https://substrate-actor.local/actor/team-a/agent-1",
	} {
		if _, _, err := parseActorSPIFFEID(id); err == nil {
			t.Errorf("parseActorSPIFFEID(%q) succeeded", id)
		}
	}
}

type fakeMinter struct {
	calls atomic.Int32
	err   error
}

func (m *fakeMinter) MintActorJWT(_ context.Context, atespace, name, aud string) (string, error) {
	m.calls.Add(1)
	if m.err != nil {
		return "", m.err
	}
	return "jwt:" + atespace + "/" + name + "@" + aud, nil
}

type fakeExchanger struct {
	calls    atomic.Int32
	lifetime time.Duration
	now      func() time.Time
	block    chan struct{}
}

func (e *fakeExchanger) Exchange(ctx context.Context, _, subjectToken, _ string, _ []string) (tokenexchange.Token, error) {
	n := e.calls.Add(1)
	if e.block != nil {
		select {
		case <-e.block:
		case <-ctx.Done():
			return tokenexchange.Token{}, status.FromContextError(ctx.Err()).Err()
		}
	}
	return tokenexchange.Token{AccessToken: subjectToken + "#" + strconv.Itoa(int(n)), ExpiresAt: e.now().Add(e.lifetime)}, nil
}

func fetch(s *Server, uri, actor string) (string, error) {
	resp, err := s.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{Uri: uri, ActorSpiffeId: actor})
	return string(resp.GetOpaqueBytes()), err
}

func TestFetchSecretPolicy(t *testing.T) {
	m := &fakeMinter{}
	s := newServer(t, m, &fakeExchanger{lifetime: time.Hour, now: time.Now})
	for name, tc := range map[string]struct {
		uri, actor string
		want       codes.Code
	}{
		"granted":           {apiURI, actorID, codes.OK},
		"bad uri":           {"ate-secret://nope/token-exchange/api", actorID, codes.InvalidArgument},
		"bad actor":         {apiURI, "spiffe://cluster.local/ns/x/sa/y", codes.PermissionDenied},
		"unknown profile":   {"ate-secret://sts/token-exchange/missing", actorID, codes.PermissionDenied},
		"profile not given": {"ate-secret://sts/token-exchange/other", actorID, codes.PermissionDenied},
		"atespace not given": {apiURI,
			"spiffe://substrate-actor.local/actor/team-b/agent-1", codes.PermissionDenied},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fetch(s, tc.uri, tc.actor); status.Code(err) != tc.want {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
	if got := m.calls.Load(); got != 1 {
		t.Errorf("minter called %d times, want 1", got)
	}
}

func TestFetchSecretTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ex := &fakeExchanger{lifetime: time.Hour, now: time.Now, block: make(chan struct{})}
		s := NewServer(testConfig(t), &fakeMinter{}, ex, time.Second)
		start := time.Now()
		if _, err := fetch(s, apiURI, actorID); status.Code(err) != codes.DeadlineExceeded {
			t.Errorf("got %v, want DeadlineExceeded", err)
		}
		if got := time.Since(start); got != time.Second {
			t.Errorf("exchange gave up after %v, want the 1s fetch timeout", got)
		}
	})
}

// fakeControl is an in-process ate-api-server Control service.
type fakeControl struct {
	ateapi.UnimplementedControlServer
	mu   sync.Mutex
	reqs []*ateapi.MintActorJwtRequest
	err  error
}

func (f *fakeControl) MintActorJwt(_ context.Context, req *ateapi.MintActorJwtRequest) (*ateapi.MintActorJwtResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	if f.err != nil {
		return nil, f.err
	}
	return &ateapi.MintActorJwtResponse{ActorJwt: "actor-jwt-for-" + req.GetActor().GetName()}, nil
}

func startControl(t *testing.T, f *fakeControl) ateapi.ControlClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	ateapi.RegisterControlServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return ateapi.NewControlClient(conn)
}

// newExchanger returns a token exchange client that trusts srv's certificate.
func newExchanger(t *testing.T, srv *httptest.Server) *tokenexchange.Client {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := tokenexchange.New(caFile)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFetchSecretEndToEnd(t *testing.T) {
	control := &fakeControl{}
	var form url.Values
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "exchanged-token", "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(sts.Close)

	cfg := testConfig(t)
	// The config accepts only Google Cloud STS, so point the profile at the
	// test server after parsing.
	p, _ := cfg.Profile("api")
	p.TokenURL = sts.URL + "/token"
	s := NewServer(cfg, ControlMinter{Client: startControl(t, control)}, newExchanger(t, sts), 0)

	if got, err := fetch(s, apiURI, actorID); err != nil || got != "exchanged-token" {
		t.Fatalf("got %q, %v", got, err)
	}
	for k, want := range map[string]string{"subject_token": "actor-jwt-for-agent-1", "audience": audience, "scope": "read"} {
		if got := form.Get(k); got != want {
			t.Errorf("form %s = %q, want %q", k, got, want)
		}
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	req := control.reqs[0]
	if req.GetActor().GetAtespace() != "team-a" || req.GetActor().GetName() != "agent-1" ||
		len(req.GetAudiences()) != 1 || req.GetAudiences()[0] != audience || req.GetExpirationSeconds() != 300 {
		t.Errorf("MintActorJwt request = %v", req)
	}
}

func TestFetchSecretMintErrors(t *testing.T) {
	for in, want := range map[codes.Code]codes.Code{
		codes.NotFound:         codes.PermissionDenied,
		codes.Unavailable:      codes.Unavailable,
		codes.DeadlineExceeded: codes.DeadlineExceeded,
		codes.PermissionDenied: codes.FailedPrecondition,
	} {
		control := &fakeControl{err: status.Error(in, "boom")}
		s := newServer(t, ControlMinter{Client: startControl(t, control)}, &fakeExchanger{})
		_, err := fetch(s, apiURI, actorID)
		if status.Code(err) != want || !strings.Contains(err.Error(), "MintActorJwt") {
			t.Errorf("MintActorJwt %v: got %v, want %v", in, err, want)
		}
	}
}
