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
	"log/slog"
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
	return NewServer(context.Background(), testConfig(t), m, e, 0)
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
	calls     atomic.Int32
	lifetime  time.Duration // zero means no expiry
	block     chan struct{}
	failFirst int32 // this many calls fail with Unavailable
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
	if n <= e.failFirst {
		return tokenexchange.Token{}, status.Error(codes.Unavailable, "exchange failed")
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

func TestFetchSecretTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ex := &fakeExchanger{lifetime: time.Hour, block: make(chan struct{})}
		s := NewServer(context.Background(), testConfig(t), &fakeMinter{}, ex, time.Second)
		start := time.Now()
		if _, err := fetch(s, apiURI, actorID); status.Code(err) != codes.DeadlineExceeded {
			t.Errorf("got %v, want DeadlineExceeded", err)
		}
		if got := time.Since(start); got != time.Second {
			t.Errorf("exchange gave up after %v, want the 1s fetch timeout", got)
		}
	})
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

		logs := recordLogs(s)

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
		count := map[string]int{}
		for _, src := range sources {
			count[src]++
		}
		if count["miss"] != 1 || count["shared"] != n-1 {
			t.Errorf("sources = %q, want one miss, the caller that exchanged, and %d shared", sources, n-1)
		}
		if got := logs.count(slog.LevelInfo, "token exchange"); got != 1 {
			t.Errorf("logged %d exchanges at Info, want 1", got)
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

func TestFetchSecretLogsAbandonedExchangeFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ex := &fakeExchanger{lifetime: time.Hour, block: make(chan struct{}), failFirst: 1}
		s := newServer(t, &fakeMinter{}, ex)
		logs := recordLogs(s)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error)
		go func() {
			_, err := s.FetchSecret(ctx, &credprovider.FetchSecretRequest{Uri: apiURI, ActorSpiffeId: actorID})
			done <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-done; status.Code(err) != codes.Canceled {
			t.Fatalf("canceled caller got %v, want Canceled", err)
		}
		if got := logs.count(slog.LevelWarn, "fetch secret failed"); got != 1 {
			t.Errorf("logged %d abandoned requests at Warn, want 1", got)
		}

		// Every caller is gone; the exchange now fails.
		close(ex.block)
		synctest.Wait()
		if got := logs.count(slog.LevelWarn, "token exchange failed"); got != 1 {
			t.Errorf("logged %d failed exchanges at Warn, want 1", got)
		}
		if got := logs.count(slog.LevelInfo, "token exchange"); got != 0 {
			t.Errorf("logged %d exchanges at Info, want 0", got)
		}
	})
}

func TestFetchSecretErrorsAreNotCached(t *testing.T) {
	t.Run("sequential", func(t *testing.T) {
		ex := &fakeExchanger{lifetime: time.Hour, failFirst: 1}
		s := newServer(t, &fakeMinter{}, ex)
		if _, err := fetch(s, apiURI, actorID); status.Code(err) != codes.Unavailable {
			t.Fatalf("first fetch: got %v, want Unavailable", err)
		}
		if _, err := fetch(s, apiURI, actorID); err != nil {
			t.Fatalf("second fetch: %v", err)
		}
		if got := ex.calls.Load(); got != 2 {
			t.Errorf("exchanges = %d, want 2 (the failure isn't cached)", got)
		}
	})
	t.Run("waiters on a failing flight", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ex := &fakeExchanger{lifetime: time.Hour, block: make(chan struct{}), failFirst: 1}
			s := newServer(t, &fakeMinter{}, ex)
			logs := recordLogs(s)

			const n = 4
			var wg sync.WaitGroup
			errs := make([]error, n)
			for i := range n {
				wg.Go(func() { _, _, errs[i] = s.fetch(context.Background(), actorID, "api") })
			}
			synctest.Wait()
			close(ex.block)
			wg.Wait()
			for i, err := range errs {
				if status.Code(err) != codes.Unavailable {
					t.Errorf("waiter %d: got %v, want Unavailable", i, err)
				}
			}
			if got := logs.count(slog.LevelWarn, "token exchange failed"); got != 1 {
				t.Errorf("logged %d failed exchanges at Warn, want 1", got)
			}
			if _, src, err := s.fetch(context.Background(), actorID, "api"); err != nil || src != "miss" || ex.calls.Load() != 2 {
				t.Errorf("after the failure: source=%q err=%v exchanges=%d, want a new exchange", src, err, ex.calls.Load())
			}
		})
	})
}

func TestFetchSecretPolicyCheckedOnWarmCache(t *testing.T) {
	ex := &fakeExchanger{lifetime: time.Hour}
	s := newServer(t, &fakeMinter{}, ex)
	if _, err := fetch(s, apiURI, actorID); err != nil {
		t.Fatal(err)
	}

	// An actor of the same name in an atespace not granted the profile.
	if _, err := fetch(s, apiURI, "spiffe://substrate-actor.local/actor/team-b/agent-1"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ungranted atespace: got %v, want PermissionDenied", err)
	}

	// The cached actor itself, once the policy no longer grants the profile.
	revoked, err := config.Parse([]byte(`
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
    team-a: ["other"]
`))
	if err != nil {
		t.Fatal(err)
	}
	s.cfg = revoked
	if _, err := fetch(s, apiURI, actorID); status.Code(err) != codes.PermissionDenied {
		t.Errorf("revoked grant with a cached token: got %v, want PermissionDenied", err)
	}
	if got := ex.calls.Load(); got != 1 {
		t.Errorf("exchanges = %d, want 1", got)
	}
}

func TestRunFlightRecheckFindsCachedToken(t *testing.T) {
	ex := &fakeExchanger{lifetime: time.Hour}
	s := newServer(t, &fakeMinter{}, ex)
	logs := recordLogs(s)
	key := cacheKey{"team-a", "agent-1", "api"}
	s.store(key, tokenexchange.Token{AccessToken: "cached", ExpiresAt: time.Now().Add(time.Hour)})
	p, _ := s.cfg.Profile("api")

	f, err := s.runFlight(key, actorID, p)
	if err != nil || f.token != "cached" || f.exchanged {
		t.Errorf("runFlight = %+v, %v; want the cached token, not exchanged", f, err)
	}
	if ex.calls.Load() != 0 || logs.count(slog.LevelInfo, "token exchange") != 0 {
		t.Errorf("exchanges = %d, Info lines = %d; want none", ex.calls.Load(), logs.count(slog.LevelInfo, "token exchange"))
	}
}

func TestReuseFor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			expiresIn time.Duration // zero means no expires_in
			want      time.Duration
		}{
			{"no expires_in", 0, unknownExpiryReuse},
			{"a third of the lifetime", time.Hour, 40 * time.Minute},
			{"30s margin", 60 * time.Second, 30 * time.Second},
			{"capped", 48 * time.Hour, maxReuse},
			{"30s left", 30 * time.Second, 0},
			{"10s left", 10 * time.Second, -20 * time.Second},
			{"already expired", -time.Minute, -90 * time.Second},
		} {
			tok := tokenexchange.Token{AccessToken: "at"}
			if tc.expiresIn != 0 {
				tok.ExpiresAt = time.Now().Add(tc.expiresIn)
			}
			if got := reuseFor(tok); got != tc.want {
				t.Errorf("%s: reuseFor = %v, want %v", tc.name, got, tc.want)
			}
			s := newServer(t, &fakeMinter{}, &fakeExchanger{})
			key := cacheKey{"team-a", "agent-1", "api"}
			stored := s.store(key, tok)
			_, cached := s.cached(key)
			if wantCached := tc.want > 0; cached != wantCached || (cached && stored != tc.want) || (!cached && stored != 0) {
				t.Errorf("%s: store = %v, cached = %v; want cached for %v only if positive", tc.name, stored, cached, tc.want)
			}
		}
	})
}

// logRecorder is a slog.Handler that keeps every record.
type logRecorder struct {
	mu   sync.Mutex
	recs []slog.Record
}

// recordLogs sends s's logs to a new logRecorder.
func recordLogs(s *Server) *logRecorder {
	r := &logRecorder{}
	s.log = slog.New(r)
	return r
}

func (r *logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *logRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec.Clone())
	return nil
}

func (r *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *logRecorder) WithGroup(string) slog.Handler      { return r }

// count returns how many records have level and msg.
func (r *logRecorder) count(level slog.Level, msg string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rec := range r.recs {
		if rec.Level == level && rec.Message == msg {
			n++
		}
	}
	return n
}

func TestFetchSecretServerContextBoundsExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		ex := &fakeExchanger{lifetime: time.Hour, block: make(chan struct{})}
		s := NewServer(ctx, testConfig(t), &fakeMinter{}, ex, 0)
		go cancel()
		if _, _, err := s.fetch(context.Background(), actorID, "api"); status.Code(err) != codes.Canceled {
			t.Errorf("got %v, want Canceled when the server context ends", err)
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
	s := NewServer(context.Background(), cfg, ControlMinter{Client: startControl(t, control)}, newExchanger(t, sts), 0)

	for range 2 {
		if got, err := fetch(s, apiURI, actorID); err != nil || got != "exchanged-token" {
			t.Fatalf("got %q, %v", got, err)
		}
	}
	for k, want := range map[string]string{"subject_token": "actor-jwt-for-agent-1", "audience": audience, "scope": "read"} {
		if got := form.Get(k); got != want {
			t.Errorf("form %s = %q, want %q", k, got, want)
		}
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.reqs) != 1 {
		t.Errorf("minted %d times, want 1 (the repeat is cached)", len(control.reqs))
	}
	req := control.reqs[0]
	if req.GetActor().GetAtespace() != "team-a" || req.GetActor().GetName() != "agent-1" ||
		len(req.GetAudiences()) != 1 || req.GetAudiences()[0] != audience || req.GetExpirationSeconds() != 3600 {
		t.Errorf("MintActorJwt request = %v", req)
	}
}

func TestFetchSecretMintErrors(t *testing.T) {
	for in, want := range map[codes.Code]codes.Code{
		codes.NotFound:          codes.PermissionDenied,
		codes.Unavailable:       codes.Unavailable,
		codes.DeadlineExceeded:  codes.DeadlineExceeded,
		codes.ResourceExhausted: codes.Unavailable,
		codes.Aborted:           codes.Unavailable,
		codes.PermissionDenied:  codes.FailedPrecondition,
		codes.Internal:          codes.FailedPrecondition,
	} {
		control := &fakeControl{err: status.Error(in, "boom")}
		s := newServer(t, ControlMinter{Client: startControl(t, control)}, &fakeExchanger{})
		_, err := fetch(s, apiURI, actorID)
		if status.Code(err) != want || !strings.Contains(err.Error(), "MintActorJwt") {
			t.Errorf("MintActorJwt %v: got %v, want %v", in, err, want)
		}
	}
}
