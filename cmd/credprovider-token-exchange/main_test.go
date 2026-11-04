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

package main

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"sigs.k8s.io/yaml"

	"go.ate.dev/substrate/api/credprovider/v1"

	"plugins.go.ate.dev/credprovider-token-exchange/internal/config"
)

// /healthz passes regardless of readiness; /readyz follows the ready flag.
func TestHealthHandler(t *testing.T) {
	var ready atomic.Bool
	h := healthHandler(&ready)

	get := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}

	if got := get("/healthz"); got != http.StatusOK {
		t.Errorf("/healthz before ready = %d, want 200", got)
	}
	if got := get("/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("/readyz before ready = %d, want 503", got)
	}

	ready.Store(true)
	if got := get("/readyz"); got != http.StatusOK {
		t.Errorf("/readyz when ready = %d, want 200", got)
	}

	ready.Store(false)
	if got := get("/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("/readyz while draining = %d, want 503", got)
	}
	if got := get("/healthz"); got != http.StatusOK {
		t.Errorf("/healthz while draining = %d, want 200", got)
	}
}

// run rejects a missing or invalid flag, or an unreadable file, before it
// dials anything or binds a port.
func TestRunValidatesFlags(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgFile, []byte(exampleConfig(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "absent")
	flags := map[string]*string{
		"server-cred-bundle":     serverBundle,
		"client-ca-file":         clientCAFile,
		"injector-identity":      injectorIdentity,
		"config":                 configFile,
		"ateapi-address":         ateapiAddr,
		"ateapi-ca-file":         ateapiCAFile,
		"ateapi-client-cert":     ateapiClientCert,
		"ateapi-server-name":     ateapiServerName,
		"token-exchange-ca-file": tokenExchangeCA,
	}
	valid := map[string]string{
		"server-cred-bundle": absent,
		"client-ca-file":     absent,
		"injector-identity":  "spiffe://cluster.local/ns/ate-system/sa/atenet-egress",
		"config":             cfgFile,
		"ateapi-address":     "dns:///api.ate-system.svc:443",
		"ateapi-ca-file":     absent,
		"ateapi-client-cert": absent,
		"ateapi-server-name": "api.ate-system.svc",
	}
	tests := []struct {
		name     string
		override map[string]string
		timeouts [2]time.Duration // fetch, drain; zero keeps the default
		wantErr  string
		wantIs   error
	}{
		{name: "no server bundle", override: map[string]string{"server-cred-bundle": ""}, wantErr: "--server-cred-bundle"},
		{name: "no client CA", override: map[string]string{"client-ca-file": ""}, wantErr: "--client-ca-file"},
		{name: "no injector identity", override: map[string]string{"injector-identity": ""}, wantErr: "--injector-identity"},
		{name: "no config", override: map[string]string{"config": ""}, wantErr: "--config"},
		{name: "no ateapi address", override: map[string]string{"ateapi-address": ""}, wantErr: "--ateapi-address"},
		{name: "no ateapi CA", override: map[string]string{"ateapi-ca-file": ""}, wantErr: "--ateapi-ca-file"},
		{name: "no ateapi client cert", override: map[string]string{"ateapi-client-cert": ""}, wantErr: "--ateapi-client-cert"},
		{name: "no ateapi server name", override: map[string]string{"ateapi-server-name": ""}, wantErr: "--ateapi-server-name"},
		{name: "fetch timeout not positive", timeouts: [2]time.Duration{-time.Second, 0}, wantErr: "--fetch-timeout"},
		{name: "drain grace not positive", timeouts: [2]time.Duration{0, -time.Second}, wantErr: "--drain-grace"},
		{name: "config unreadable", override: map[string]string{"config": absent}, wantErr: "config", wantIs: fs.ErrNotExist},
		{name: "token exchange CA unreadable", override: map[string]string{"token-exchange-ca-file": absent}, wantErr: "token exchange CA file", wantIs: fs.ErrNotExist},
		{name: "client CA unreadable", wantErr: "server credentials", wantIs: fs.ErrNotExist},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := map[string]string{}
			for name, p := range flags {
				orig[name] = *p
			}
			origFetch, origDrain := *fetchTimeout, *drainGrace
			t.Cleanup(func() {
				for name, p := range flags {
					*p = orig[name]
				}
				*fetchTimeout, *drainGrace = origFetch, origDrain
			})
			for name, p := range flags {
				*p = valid[name]
				if v, ok := tc.override[name]; ok {
					*p = v
				}
			}
			if tc.timeouts[0] != 0 {
				*fetchTimeout = tc.timeouts[0]
			}
			if tc.timeouts[1] != 0 {
				*drainGrace = tc.timeouts[1]
			}

			err := run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("run() error = %v, want one mentioning %q", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("run() error = %v, want one wrapping %v", err, tc.wantIs)
			}
		})
	}
}

// exampleConfig returns config.yaml from config/config-example.yaml.
func exampleConfig(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../config/config-example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := yaml.Unmarshal(b, &cm); err != nil {
		t.Fatal(err)
	}
	return cm.Data["config.yaml"]
}

func TestConfigExampleParses(t *testing.T) {
	if _, err := config.Parse([]byte(exampleConfig(t))); err != nil {
		t.Errorf("config-example.yaml: %v", err)
	}
}

func TestBuildVersionPrefersExplicitVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "v9.9.9"
	if got := buildVersion(); !strings.HasPrefix(got, "v9.9.9") {
		t.Errorf("buildVersion() = %q, want it to start with v9.9.9", got)
	}
	version = ""
	if got := buildVersion(); got == "" {
		t.Error("buildVersion() is empty without an explicit version")
	}
}

// blockingProvider blocks FetchSecret until release is closed or the call is
// canceled, closing entered once the call starts.
type blockingProvider struct {
	credprovider.UnimplementedCredentialProviderServer
	entered chan struct{}
	release chan struct{}
}

func (p *blockingProvider) FetchSecret(ctx context.Context, _ *credprovider.FetchSecretRequest) (*credprovider.FetchSecretResponse, error) {
	close(p.entered)
	select {
	case <-p.release:
		return &credprovider.FetchSecretResponse{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startBlockingServer serves p in memory and starts one FetchSecret against it,
// returning the server and the call's result.
func startBlockingServer(t *testing.T, p *blockingProvider) (*grpc.Server, <-chan error) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	credprovider.RegisterCredentialProviderServer(srv, p)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	result := make(chan error, 1)
	go func() {
		_, err := credprovider.NewCredentialProviderClient(conn).FetchSecret(context.Background(), &credprovider.FetchSecretRequest{})
		result <- err
	}()
	select {
	case <-p.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("FetchSecret never reached the server")
	}
	return srv, result
}

// gracefulStop returns once an in-flight call completes within the grace period.
func TestGracefulStopDrains(t *testing.T) {
	p := &blockingProvider{entered: make(chan struct{}), release: make(chan struct{})}
	srv, result := startBlockingServer(t, p)

	stopped := make(chan struct{})
	go func() {
		gracefulStop(srv, time.Minute)
		close(stopped)
	}()
	close(p.release)
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("gracefulStop did not return after the in-flight call finished")
	}
	if err := <-result; err != nil {
		t.Errorf("in-flight FetchSecret = %v, want it to complete", err)
	}
}

// gracefulStop cuts off a call still running when the grace period ends.
func TestGracefulStopForcesAfterGrace(t *testing.T) {
	const grace = 100 * time.Millisecond
	p := &blockingProvider{entered: make(chan struct{}), release: make(chan struct{})}
	srv, result := startBlockingServer(t, p)

	start := time.Now()
	gracefulStop(srv, grace)
	if elapsed := time.Since(start); elapsed < grace || elapsed > 50*grace {
		t.Errorf("gracefulStop returned after %v, want about %v", elapsed, grace)
	}
	if err := <-result; err == nil {
		t.Error("in-flight FetchSecret succeeded, want it cut off")
	}
}
