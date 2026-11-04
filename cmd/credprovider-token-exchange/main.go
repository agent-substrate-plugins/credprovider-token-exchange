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

// Command credprovider-token-exchange serves substrate's CredentialProvider
// gRPC API by exchanging an actor's Substrate-minted JWT for an access token at
// an RFC 8693 token endpoint.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	ateapi "go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/api/credprovider/v1"

	"plugins.go.ate.dev/credprovider-token-exchange/internal/ateapiclient"
	"plugins.go.ate.dev/credprovider-token-exchange/internal/config"
	"plugins.go.ate.dev/credprovider-token-exchange/internal/mtls"
	"plugins.go.ate.dev/credprovider-token-exchange/internal/provider"
	"plugins.go.ate.dev/credprovider-token-exchange/internal/tokenexchange"
)

var (
	listenAddr       = flag.String("listen-address", ":50051", "gRPC listen address")
	healthAddr       = flag.String("health-address", ":9090", "HTTP listen address for /healthz and /readyz")
	serverBundle     = flag.String("server-cred-bundle", "", "credential bundle (PKCS#8 key and certificate chain) presented for serving TLS (required)")
	clientCAFile     = flag.String("client-ca-file", "", "trust bundle the caller's client certificate must chain to (required)")
	injectorIdentity = flag.String("injector-identity", "", "SPIFFE ID the caller's client certificate must carry: substrate's egress gateway (required)")
	configFile       = flag.String("config", "", "profiles and policy file (required)")
	ateapiAddr       = flag.String("ateapi-address", "", "gRPC target of ate-api-server (required)")
	ateapiCAFile     = flag.String("ateapi-ca-file", "", "trust bundle the ate-api-server certificate must chain to (required)")
	ateapiClientCert = flag.String("ateapi-client-cert", "", "credential bundle presented to ate-api-server (required)")
	ateapiServerName = flag.String("ateapi-server-name", "", "DNS name the ate-api-server certificate must carry (required)")
	tokenExchangeCA  = flag.String("token-exchange-ca-file", "", "PEM certificates trusted for token exchange endpoints, in addition to the system roots. A missing file or one with no certificates fails startup")
	fetchTimeout     = flag.Duration("fetch-timeout", provider.DefaultFetchTimeout, "time limit for minting and exchanging one token; keep it under the egress gateway's 4s credential injection timeout")
	logLevel         = flag.String("log-level", "info", "one of debug, info, warn, error")
	drainGrace       = flag.Duration("drain-grace", 5*time.Second, "how long to wait for in-flight RPCs on shutdown before a hard stop")
)

// preDrainDelay gives endpoint controllers time to stop routing to the pod
// after it reports not ready.
const preDrainDelay = 2 * time.Second

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version string

func main() {
	flag.Parse()
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid --log-level %q: %v\n", *logLevel, err)
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	slog.Info("starting credprovider-token-exchange", slog.String("version", buildVersion()))
	if err := run(context.Background()); err != nil {
		slog.Error("credprovider-token-exchange exited with error", slog.Any("err", err))
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	for _, f := range []struct{ name, value string }{
		{"--server-cred-bundle", *serverBundle},
		{"--client-ca-file", *clientCAFile},
		{"--injector-identity", *injectorIdentity},
		{"--config", *configFile},
		{"--ateapi-address", *ateapiAddr},
		{"--ateapi-ca-file", *ateapiCAFile},
		{"--ateapi-client-cert", *ateapiClientCert},
		{"--ateapi-server-name", *ateapiServerName},
	} {
		if f.value == "" {
			return fmt.Errorf("%s is required", f.name)
		}
	}
	if *fetchTimeout <= 0 {
		return fmt.Errorf("--fetch-timeout must be positive, got %v", *fetchTimeout)
	}
	if *drainGrace <= 0 {
		return fmt.Errorf("--drain-grace must be positive, got %v", *drainGrace)
	}

	cfg, err := config.Load(*configFile)
	if err != nil {
		return fmt.Errorf("config %s: %w", *configFile, err)
	}
	slog.Info("loaded config", slog.String("file", *configFile), slog.String("provider_name", cfg.ProviderName), slog.Int("profiles", len(cfg.Profiles)))

	exchanger, err := tokenexchange.New(*tokenExchangeCA)
	if err != nil {
		return err
	}

	creds, err := mtls.ServerCredentials(mtls.Config{
		ServerBundle:   *serverBundle,
		ClientCAFile:   *clientCAFile,
		CallerIdentity: *injectorIdentity,
	})
	if err != nil {
		return fmt.Errorf("server credentials: %w", err)
	}

	conn, err := ateapiclient.Dial(ateapiclient.Config{
		Address:          *ateapiAddr,
		CAFile:           *ateapiCAFile,
		ServerName:       *ateapiServerName,
		ClientCredBundle: *ateapiClientCert,
	})
	if err != nil {
		return fmt.Errorf("dialing ate-api-server: %w", err)
	}
	defer conn.Close()
	flightCtx, cancelFlights := context.WithCancel(ctx)
	defer cancelFlights()

	srv := grpc.NewServer(grpc.Creds(creds), grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: time.Hour}))
	credprovider.RegisterCredentialProviderServer(srv, provider.NewServer(
		flightCtx,
		cfg,
		provider.ControlMinter{Client: ateapi.NewControlClient(conn)},
		exchanger,
		*fetchTimeout,
	))

	grpcLis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listenAddr, err)
	}
	healthLis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *healthAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *healthAddr, err)
	}
	var ready atomic.Bool
	healthSrv := &http.Server{Handler: healthHandler(&ready), ReadHeaderTimeout: 10 * time.Second}
	healthDone := make(chan error, 1)
	go func() { healthDone <- healthSrv.Serve(healthLis) }()

	shutdownCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownErr := make(chan error, 1)
	go func() {
		var err error
		select {
		case <-shutdownCtx.Done():
			slog.Info("shutting down")
		case err = <-healthDone:
			err = fmt.Errorf("health server: %w", err)
		}
		ready.Store(false)
		time.Sleep(preDrainDelay)
		gracefulStop(srv, *drainGrace)
		_ = healthSrv.Close()
		shutdownErr <- err
	}()

	ready.Store(true)
	slog.Info("credprovider-token-exchange listening",
		slog.String("address", grpcLis.Addr().String()),
		slog.String("health_address", healthLis.Addr().String()),
		slog.String("required_caller_san", *injectorIdentity),
		slog.String("ateapi_address", *ateapiAddr))
	if err := srv.Serve(grpcLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serving: %w", err)
	}
	return <-shutdownErr
}

// gracefulStop lets in-flight RPCs finish for up to grace, then forces the
// server down.
func gracefulStop(srv *grpc.Server, grace time.Duration) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(grace):
		slog.Warn("graceful shutdown timed out; forcing stop", slog.Duration("grace", grace))
		srv.Stop()
	}
}

// healthHandler serves /healthz, which always succeeds, and /readyz, which
// succeeds only while ready is set.
func healthHandler(ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// buildVersion returns the release or module version, else "dev", plus the VCS
// revision when the build recorded one.
func buildVersion() string {
	v := version
	info, ok := debug.ReadBuildInfo()
	if !ok {
		if v == "" {
			return "dev"
		}
		return v
	}
	if v == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		v = info.Main.Version
	}
	if v == "" {
		v = "dev"
	}
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return v
	}
	if modified == "true" {
		revision += "-dirty"
	}
	return v + " commit=" + revision
}
