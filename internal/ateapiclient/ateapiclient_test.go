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

package ateapiclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ateapi "go.ate.dev/substrate/api/ateapi/v1"

	"plugins.go.ate.dev/credprovider-token-exchange/internal/mtls"
)

const clientSPIFFE = "spiffe://cluster.local/ns/ate-system/sa/credprovider-token-exchange"

type control struct {
	ateapi.UnimplementedControlServer
}

func (control) MintActorJwt(context.Context, *ateapi.MintActorJwtRequest) (*ateapi.MintActorJwtResponse, error) {
	return &ateapi.MintActorJwtResponse{ActorJwt: "jwt"}, nil
}

func TestDialMutualTLS(t *testing.T) {
	dir := t.TempDir()
	serverCA, serverCAKey := newCA(t)
	clientCA, clientCAKey := newCA(t)
	serverCAFile := writePEM(t, dir, "server-ca.pem", serverCA)
	clientCAFile := writePEM(t, dir, "client-ca.pem", clientCA)
	serverBundle := writeBundle(t, dir, "server.pem", serverCA, serverCAKey, []string{"api.ate-system.svc"}, nil)
	clientBundle := writeBundle(t, dir, "client.pem", clientCA, clientCAKey, nil, []string{clientSPIFFE})

	creds, err := mtls.ServerCredentials(mtls.Config{ServerBundle: serverBundle, ClientCAFile: clientCAFile, CallerIdentity: clientSPIFFE})
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	ateapi.RegisterControlServer(srv, control{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	for name, tc := range map[string]struct {
		serverName string
		want       codes.Code
	}{
		"ok":                {"api.ate-system.svc", codes.OK},
		"wrong server name": {"other.ate-system.svc", codes.Unavailable},
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := Dial(Config{
				Address:          "dns:///" + lis.Addr().String(),
				CAFile:           serverCAFile,
				ServerName:       tc.serverName,
				ClientCredBundle: clientBundle,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = ateapi.NewControlClient(conn).MintActorJwt(ctx, &ateapi.MintActorJwtRequest{})
			if status.Code(err) != tc.want {
				t.Errorf("MintActorJwt: %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDialRequiresFiles(t *testing.T) {
	if _, err := Dial(Config{Address: "dns:///x:1", CAFile: "/nonexistent", ServerName: "x", ClientCredBundle: "/nonexistent"}); err == nil {
		t.Error("Dial succeeded without readable bundles")
	}
}

func TestDialRequiresServerName(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := newCA(t)
	_, err := Dial(Config{
		Address:          "dns:///x:1",
		CAFile:           writePEM(t, dir, "ca.pem", ca),
		ClientCredBundle: writeBundle(t, dir, "client.pem", ca, caKey, nil, []string{clientSPIFFE}),
	})
	if err == nil || !strings.Contains(err.Error(), "server name") {
		t.Errorf("Dial without a server name: %v, want an error", err)
	}
}

func TestDialReloadsCAFile(t *testing.T) {
	dir := t.TempDir()
	serverCA, serverCAKey := newCA(t)
	otherCA, _ := newCA(t)
	clientCA, clientCAKey := newCA(t)
	caFile := writePEM(t, dir, "server-ca.pem", otherCA)
	lis := startServer(t, dir, serverCA, serverCAKey, clientCA)
	conn, err := Dial(Config{
		Address:          "dns:///" + lis.Addr().String(),
		CAFile:           caFile,
		ServerName:       "api.ate-system.svc",
		ClientCredBundle: writeBundle(t, dir, "client.pem", clientCA, clientCAKey, nil, []string{clientSPIFFE}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := ateapi.NewControlClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.MintActorJwt(ctx, &ateapi.MintActorJwtRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("with the wrong CA: %v, want Unavailable", err)
	}
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCA.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(caFile, later, later); err != nil {
		t.Fatal(err)
	}
	if _, err := client.MintActorJwt(ctx, &ateapi.MintActorJwtRequest{}, grpc.WaitForReady(true)); err != nil {
		t.Errorf("after the CA file changed: %v", err)
	}
}

func startServer(t *testing.T, dir string, serverCA *x509.Certificate, serverCAKey *ecdsa.PrivateKey, clientCA *x509.Certificate) net.Listener {
	t.Helper()
	creds, err := mtls.ServerCredentials(mtls.Config{
		ServerBundle:   writeBundle(t, dir, "server.pem", serverCA, serverCAKey, []string{"api.ate-system.svc"}, nil),
		ClientCAFile:   writePEM(t, dir, "client-ca.pem", clientCA),
		CallerIdentity: clientSPIFFE,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	ateapi.RegisterControlServer(srv, control{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis
}

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func writePEM(t *testing.T, dir, name string, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeBundle(t *testing.T, dir, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames, uris []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []*url.URL
	for _, u := range uris {
		p, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, p)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
		URIs:         parsed,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
