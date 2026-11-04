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
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
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
	audience = "https://api.example.com"
	apiURI   = "ate-secret://sts/token-exchange/api"
)

func testConfig(t *testing.T, tokenURL string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`
providerName: sts
profiles:
- name: api
  tokenUrl: ` + tokenURL + `
  audience: ` + audience + `
  scopes: ["read"]
- name: sts-aud
  tokenUrl: ` + tokenURL + `
  subjectTokenAudience: https://sts.example.com
- name: other
  tokenUrl: ` + tokenURL + `
  audience: ` + audience + `
policy:
  atespaces:
    team-a: ["api", "sts-aud"]
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newServer(t *testing.T, m Minter, e Exchanger) *Server {
	t.Helper()
	return NewServer(context.Background(), testConfig(t, "https://sts.example.com"), m, e, 0)
}

func TestParseURI(t *testing.T) {
	s := newServer(t, nil, nil)
	for uri, want := range map[string]string{
		apiURI: "api",
		"ate-secret://sts/token-exchange/sts-aud": "sts-aud",
	} {
		if got, err := s.parseURI(uri); err != nil || got != want {
			t.Errorf("parseURI(%q) = %q, %v; want %q", uri, got, err, want)
		}
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
	block bool
}

func (m *fakeMinter) MintActorJWT(ctx context.Context, atespace, name, aud string) (string, error) {
	m.calls.Add(1)
	if m.block {
		<-ctx.Done()
		return "", status.FromContextError(ctx.Err()).Err()
	}
	if m.err != nil {
		return "", m.err
	}
	return "jwt:" + atespace + "/" + name + "@" + aud, nil
}

type fakeExchanger struct {
	calls    atomic.Int32
	lifetime time.Duration // zero means no expiry
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
	t := tokenexchange.Token{AccessToken: subjectToken + "#" + strconv.Itoa(int(n))}
	if e.lifetime > 0 {
		t.ExpiresAt = time.Now().Add(e.lifetime)
	}
	return t, nil
}

func fetch(s *Server, uri, actor string) (string, error) {
	resp, err := s.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{Uri: uri, ActorSpiffeId: actor})
	return string(resp.GetOpaqueBytes()), err
}

func TestFetchSecretPolicy(t *testing.T) {
	m := &fakeMinter{}
	s := newServer(t, m, &fakeExchanger{lifetime: time.Hour})
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

func TestFetchSecretCacheLifetime(t *testing.T) {
	for name, tc := range map[string]struct {
		lifetime         time.Duration
		cachedFor        time.Duration // still cached just before this
		wantNoCacheAtAll bool
	}{
		"a third of the lifetime remains": {lifetime: time.Hour, cachedFor: 40 * time.Minute},
		"30s remain":                      {lifetime: 60 * time.Second, cachedFor: 30 * time.Second},
		"capped at maxReuse":              {lifetime: 48 * time.Hour, cachedFor: maxReuse},
		"unknown expiry":                  {lifetime: 0, cachedFor: unknownExpiryReuse},
		"30s or less is never cached":     {lifetime: 30 * time.Second, wantNoCacheAtAll: true},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newServer(t, &fakeMinter{}, &fakeExchanger{lifetime: tc.lifetime})
				first, err := fetch(s, apiURI, actorID)
				if err != nil {
					t.Fatal(err)
				}
				if tc.wantNoCacheAtAll {
					if got, _ := fetch(s, apiURI, actorID); got == first {
						t.Errorf("token was cached")
					}
					return
				}
				time.Sleep(tc.cachedFor - time.Second)
				if got, _ := fetch(s, apiURI, actorID); got != first {
					t.Errorf("before refresh: got %q, want cached %q", got, first)
				}
				time.Sleep(time.Second)
				if got, _ := fetch(s, apiURI, actorID); got == first {
					t.Errorf("at refresh point: got cached token %q", got)
				}
			})
		})
	}
}

func TestFetchSecretCachesPerActor(t *testing.T) {
	ex := &fakeExchanger{lifetime: time.Hour}
	s := newServer(t, &fakeMinter{}, ex)
	for _, actor := range []string{actorID, "spiffe://substrate-actor.local/actor/team-a/agent-2", actorID} {
		if _, err := fetch(s, apiURI, actor); err != nil {
			t.Fatal(err)
		}
	}
	if got := ex.calls.Load(); got != 2 {
		t.Errorf("exchanges = %d, want 2 (one per actor)", got)
	}
}

func TestFetchSecretSingleflight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ex := &fakeExchanger{lifetime: time.Hour, block: make(chan struct{})}
		s := newServer(t, &fakeMinter{}, ex)

		const n = 8
		var wg sync.WaitGroup
		sources := make([]string, n)
		for i := range n {
			wg.Go(func() {
				var err error
				if _, sources[i], err = s.fetch(context.Background(), actorID, "api"); err != nil {
					t.Error(err)
				}
			})
		}
		synctest.Wait()
		close(ex.block)
		wg.Wait()

		if got := ex.calls.Load(); got != 1 {
			t.Errorf("exchanges = %d, want 1", got)
		}
		for _, src := range sources {
			if src != "shared" {
				t.Errorf("sources = %q, want all shared", sources)
				break
			}
		}
	})
}

func TestFetchSecretCallerCancelDoesNotAbortExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ex := &fakeExchanger{lifetime: time.Hour, block: make(chan struct{})}
		s := newServer(t, &fakeMinter{}, ex)

		ctx, cancel := context.WithCancel(context.Background())
		var src string
		var err error
		done := make(chan struct{})
		go func() {
			_, src, err = s.fetch(ctx, actorID, "api")
			close(done)
		}()
		synctest.Wait()
		cancel()
		<-done
		if status.Code(err) != codes.Canceled || src != "abandoned" {
			t.Errorf("canceled caller got %q, %v; want abandoned, Canceled", src, err)
		}
		close(ex.block)
		synctest.Wait()
		if _, src, err := s.fetch(context.Background(), actorID, "api"); err != nil || src != "hit" || ex.calls.Load() != 1 {
			t.Errorf("retry: source=%q err=%v exchanges=%d, want a cached token", src, err, ex.calls.Load())
		}
	})
}

func TestFetchSecretServerContextBoundsExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		ex := &fakeExchanger{lifetime: time.Hour, block: make(chan struct{})}
		s := NewServer(ctx, testConfig(t, "https://sts.example.com"), &fakeMinter{}, ex, 0)
		go cancel()
		if _, _, err := s.fetch(context.Background(), actorID, "api"); status.Code(err) != codes.Canceled {
			t.Errorf("got %v, want Canceled when the server context ends", err)
		}
	})
}

func TestFetchSecretTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ex := &fakeExchanger{lifetime: time.Hour, block: make(chan struct{})}
		s := NewServer(context.Background(), testConfig(t, "https://sts.example.com"), &fakeMinter{}, ex, time.Second)
		start := time.Now()
		if _, _, err := s.fetch(context.Background(), actorID, "api"); status.Code(err) != codes.DeadlineExceeded {
			t.Errorf("got %v, want DeadlineExceeded", err)
		}
		if got := time.Since(start); got != time.Second {
			t.Errorf("exchange gave up after %v, want the 1s fetch timeout", got)
		}
	})
}

func TestFetchSecretMintTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newServer(t, &fakeMinter{block: true}, &fakeExchanger{})
		start := time.Now()
		if _, _, err := s.fetch(context.Background(), actorID, "api"); status.Code(err) != codes.DeadlineExceeded {
			t.Errorf("got %v, want DeadlineExceeded", err)
		}
		if got := time.Since(start); got != maxMintTimeout {
			t.Errorf("mint gave up after %v, want %v", got, maxMintTimeout)
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

// recordingExchanger records the exchanges it is asked for.
type recordingExchanger struct {
	mu    sync.Mutex
	calls []exchangeCall
}

type exchangeCall struct {
	tokenURL, subjectToken, audience string
	scopes                           []string
}

func (e *recordingExchanger) Exchange(_ context.Context, tokenURL, subjectToken, audience string, scopes []string) (tokenexchange.Token, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, exchangeCall{tokenURL, subjectToken, audience, scopes})
	return tokenexchange.Token{AccessToken: "exchanged-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestFetchSecretEndToEnd(t *testing.T) {
	control := &fakeControl{}
	ex := &recordingExchanger{}
	s := NewServer(context.Background(), testConfig(t, "https://sts.example.com/token"), ControlMinter{Client: startControl(t, control)}, ex, 0)

	for _, uri := range []string{apiURI, "ate-secret://sts/token-exchange/sts-aud", apiURI} {
		if got, err := fetch(s, uri, actorID); err != nil || got != "exchanged-token" {
			t.Fatalf("%s: got %q, %v", uri, got, err)
		}
	}

	ex.mu.Lock()
	defer ex.mu.Unlock()
	want := []exchangeCall{
		{"https://sts.example.com/token", "actor-jwt-for-agent-1", audience, []string{"read"}},
		{"https://sts.example.com/token", "actor-jwt-for-agent-1", "", nil},
	}
	if diff := cmp.Diff(want, ex.calls, cmp.AllowUnexported(exchangeCall{})); diff != "" {
		t.Errorf("exchanges (-want +got), the repeat being cached:\n%s", diff)
	}

	control.mu.Lock()
	defer control.mu.Unlock()
	for i, want := range []string{audience, "https://sts.example.com"} {
		req := control.reqs[i]
		if req.GetActor().GetAtespace() != "team-a" || req.GetActor().GetName() != "agent-1" ||
			len(req.GetAudiences()) != 1 || req.GetAudiences()[0] != want || req.GetExpirationSeconds() != 300 {
			t.Errorf("MintActorJwt request %d = %v, want audience %q", i, req, want)
		}
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
