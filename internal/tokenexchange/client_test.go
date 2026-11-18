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

package tokenexchange

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	subjectToken = "subject.jwt.token"
	audience     = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ate/providers/actors"
)

// newTestServer starts a TLS server running handler at /token and returns it
// with a Client that trusts its certificate.
func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", handler)
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	c, err := New(writeCAFile(t, srv))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, c
}

func writeCAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func respond(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
}

func TestExchangeSendsTokenExchangeForm(t *testing.T) {
	for _, tt := range []struct {
		name     string
		audience string
		scopes   []string
		want     url.Values
	}{{
		name:     "scopes are space-joined",
		audience: audience,
		scopes:   []string{"https://www.googleapis.com/auth/cloud-platform", "read"},
		want: url.Values{
			"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":        {subjectToken},
			"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
			"audience":             {audience},
			"scope":                {"https://www.googleapis.com/auth/cloud-platform read"},
			"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		},
	}, {
		name:     "no scope without scopes",
		audience: audience,
		want: url.Values{
			"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":        {subjectToken},
			"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
			"audience":             {audience},
			"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		},
	}, {
		name: "no audience without audience",
		want: url.Values{
			"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":        {subjectToken},
			"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
			"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		},
	}} {
		t.Run(tt.name, func(t *testing.T) {
			var got url.Values
			srv, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, want POST", r.Method)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
					t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", ct)
				}
				if err := r.ParseForm(); err != nil {
					t.Errorf("ParseForm: %v", err)
				}
				got = r.PostForm
				respond(http.StatusOK, `{"access_token":"at","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":600}`)(w, r)
			})
			if _, err := c.Exchange(t.Context(), srv.URL+"/token", subjectToken, tt.audience, tt.scopes); err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("form (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExchangeReturnsToken(t *testing.T) {
	for _, tt := range []struct {
		name          string
		body          string
		wantToken     string // fake.access.token unless set
		wantExpiresIn time.Duration
	}{{
		name:          "with expires_in",
		body:          `{"access_token":"fake.access.token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":600}`,
		wantExpiresIn: 600 * time.Second,
	}, {
		name: "without expires_in or issued_token_type",
		body: `{"access_token":"fake.access.token","token_type":"Bearer"}`,
	}, {
		name:          "with an expires_in too large for a Duration",
		body:          `{"access_token":"fake.access.token","expires_in":9223372036854775807}`,
		wantExpiresIn: maxExpiresIn * time.Second,
	}, {
		name:      "with a space in access_token",
		body:      `{"access_token":"fake access token"}`,
		wantToken: "fake access token",
	}, {
		name: "with token_type in another case",
		body: `{"access_token":"fake.access.token","token_type":"bearer"}`,
	}} {
		t.Run(tt.name, func(t *testing.T) {
			srv, c := newTestServer(t, respond(http.StatusOK, tt.body))
			before := time.Now()
			tok, err := c.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil)
			after := time.Now()
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			want := tt.wantToken
			if want == "" {
				want = "fake.access.token"
			}
			if tok.AccessToken != want {
				t.Errorf("AccessToken = %q, want %q", tok.AccessToken, want)
			}
			if tt.wantExpiresIn == 0 {
				if !tok.ExpiresAt.IsZero() {
					t.Errorf("ExpiresAt = %v, want zero", tok.ExpiresAt)
				}
				return
			}
			if tok.ExpiresAt.Before(before.Add(tt.wantExpiresIn)) || tok.ExpiresAt.After(after.Add(tt.wantExpiresIn)) {
				t.Errorf("ExpiresAt = %v, want %v after the exchange", tok.ExpiresAt, tt.wantExpiresIn)
			}
		})
	}
}

func TestExchangeErrors(t *testing.T) {
	oauthError := func(code string) string {
		return fmt.Sprintf(`{"error":%q,"error_description":"details"}`, code)
	}
	for _, tt := range []struct {
		name     string
		status   int
		body     string
		wantCode codes.Code
	}{
		{"invalid_grant", http.StatusBadRequest, oauthError("invalid_grant"), codes.PermissionDenied},
		{"invalid_target", http.StatusBadRequest, oauthError("invalid_target"), codes.PermissionDenied},
		{"unauthorized_client", http.StatusUnauthorized, oauthError("unauthorized_client"), codes.PermissionDenied},
		{"invalid_scope", http.StatusBadRequest, oauthError("invalid_scope"), codes.PermissionDenied},
		{"403 access_denied", http.StatusForbidden, oauthError("access_denied"), codes.PermissionDenied},
		{"403 without an error code", http.StatusForbidden, "forbidden", codes.PermissionDenied},
		{"access_denied, an authorization endpoint code", http.StatusBadRequest, oauthError("access_denied"), codes.FailedPrecondition},
		{"invalid_request", http.StatusBadRequest, oauthError("invalid_request"), codes.FailedPrecondition},
		{"invalid_client", http.StatusUnauthorized, oauthError("invalid_client"), codes.FailedPrecondition},
		{"unsupported_grant_type", http.StatusBadRequest, oauthError("unsupported_grant_type"), codes.FailedPrecondition},
		{"400 without an error code", http.StatusBadRequest, "bad request", codes.FailedPrecondition},
		{"404", http.StatusNotFound, "not found", codes.FailedPrecondition},
		{"429", http.StatusTooManyRequests, "slow down", codes.Unavailable},
		{"500", http.StatusInternalServerError, "", codes.Unavailable},
		{"503", http.StatusServiceUnavailable, oauthError("temporarily_unavailable"), codes.Unavailable},
		{"200 with a body that is not JSON", http.StatusOK, "<html>", codes.Unavailable},
		{"200 without access_token", http.StatusOK, `{"token_type":"Bearer","expires_in":600}`, codes.Unavailable},
		{"200 with another issued_token_type", http.StatusOK, `{"access_token":"at","issued_token_type":"urn:ietf:params:oauth:token-type:jwt"}`, codes.Unavailable},
		{"200 with a control character in access_token", http.StatusOK, `{"access_token":"at\r\nX-Injected: 1"}`, codes.Unavailable},
		{"200 with non-ASCII in access_token", http.StatusOK, `{"access_token":"atÿ"}`, codes.Unavailable},
		{"200 with DEL in access_token", http.StatusOK, `{"access_token":"at\u007f"}`, codes.Unavailable},
		{"200 with token_type DPoP", http.StatusOK, `{"access_token":"at","token_type":"DPoP"}`, codes.Unavailable},
		{"200 with token_type N_A", http.StatusOK, `{"access_token":"at","token_type":"N_A"}`, codes.Unavailable},
		{"200 with a zero expires_in", http.StatusOK, `{"access_token":"at","expires_in":0}`, codes.Unavailable},
		{"200 with a negative expires_in", http.StatusOK, `{"access_token":"at","expires_in":-5}`, codes.Unavailable},
		{"200 over 1 MiB", http.StatusOK, `{"access_token":"at"}` + strings.Repeat(" ", maxResponseBytes), codes.Unavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, c := newTestServer(t, respond(tt.status, tt.body))
			_, err := c.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil)
			if got := status.Code(err); got != tt.wantCode {
				t.Fatalf("Exchange error = %v (code %v), want code %v", err, got, tt.wantCode)
			}
			if strings.Contains(err.Error(), subjectToken) {
				t.Errorf("error %q contains the subject token", err)
			}
		})
	}
}

func TestExchangeDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Bool
	srv, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("redirected") {
			followed.Store(true)
			respond(http.StatusOK, `{"access_token":"at"}`)(w, r)
			return
		}
		http.Redirect(w, r, "/token?redirected", http.StatusTemporaryRedirect)
	})
	_, err := c.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("Exchange error = %v (code %v), want code %v", err, got, codes.FailedPrecondition)
	}
	if followed.Load() {
		t.Error("the client followed the redirect")
	}
}

func TestExchangeRejectsPlainHTTP(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		respond(http.StatusOK, `{"access_token":"at"}`)(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("Exchange error = %v (code %v), want code %v", err, got, codes.FailedPrecondition)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("the server got %d requests, want 0", n)
	}
}

func TestExchangeReportsUnparsedErrorBody(t *testing.T) {
	long := strings.Repeat("b", maxDetailBytes+50)
	for _, tt := range []struct {
		name   string
		status int
		body   string
		want   string // the error's suffix after "token endpoint returned <status>"
	}{
		{"403 plain text", http.StatusForbidden, "blocked by policy", `: body "blocked by policy"`},
		{"403 with an error object", http.StatusForbidden, `{"error":{"code":403}}`, `: body "{\"error\":{\"code\":403}}"`},
		{"500 plain text", http.StatusInternalServerError, "upstream down", `: body "upstream down"`},
		{"long body is clipped", http.StatusBadGateway, long, fmt.Sprintf(": body %q", long[:maxDetailBytes])},
		{"empty body", http.StatusForbidden, "", ""},
		{"OAuth error", http.StatusForbidden, `{"error":"access_denied"}`, `: error "access_denied", error_description ""`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, c := newTestServer(t, respond(tt.status, tt.body))
			_, err := c.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil)
			want := fmt.Sprintf("token endpoint returned %d%s", tt.status, tt.want)
			if got := status.Convert(err).Message(); got != want {
				t.Errorf("Exchange error message = %q, want %q", got, want)
			}
		})
	}
}

func TestExchangeClipsErrorDescription(t *testing.T) {
	description := strings.Repeat("d", maxDetailBytes+50)
	srv, c := newTestServer(t, respond(http.StatusBadRequest, fmt.Sprintf(`{"error":"invalid_request","error_description":%q}`, description)))
	_, err := c.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil)
	if err == nil {
		t.Fatal("Exchange succeeded, want an error")
	}
	if !strings.Contains(err.Error(), `"`+description[:maxDetailBytes]+`"`) {
		t.Errorf("error %q does not carry the description clipped to %d bytes", err, maxDetailBytes)
	}
}

func TestExchangeClipsParseError(t *testing.T) {
	srv, c := newTestServer(t, respond(http.StatusOK, `{"access_token":"at","expires_in":`+strings.Repeat("9", 4096)+`}`))
	_, err := c.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil)
	if status.Code(err) != codes.Unavailable || len(err.Error()) > 2*maxDetailBytes {
		t.Errorf("Exchange error = %.300s... (%d bytes), want code Unavailable within %d bytes", err, len(err.Error()), 2*maxDetailBytes)
	}
}

func TestExchangeTruncatedResponse(t *testing.T) {
	srv, c := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"access_token"`)
	})
	_, err := c.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil)
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("Exchange error = %v (code %v), want code %v", err, got, codes.Unavailable)
	}
}

func TestExchangeHonorsContextDeadline(t *testing.T) {
	srv, c := newTestServer(t, respond(http.StatusOK, `{"access_token":"at"}`))
	ctx, cancel := context.WithDeadline(t.Context(), time.Now())
	defer cancel()
	_, err := c.Exchange(ctx, srv.URL+"/token", subjectToken, audience, nil)
	if got := status.Code(err); got != codes.DeadlineExceeded {
		t.Errorf("Exchange error = %v (code %v), want code %v", err, got, codes.DeadlineExceeded)
	}
}

func TestExchangeCanceledContext(t *testing.T) {
	srv, c := newTestServer(t, respond(http.StatusOK, `{"access_token":"at"}`))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := c.Exchange(ctx, srv.URL+"/token", subjectToken, audience, nil)
	if got := status.Code(err); got != codes.Canceled {
		t.Errorf("Exchange error = %v (code %v), want code %v", err, got, codes.Canceled)
	}
}

// roundTripFunc is an http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ctxBody is a response body whose Read calls onRead, then waits for ctx to end
// and fails with its error.
type ctxBody struct {
	ctx    context.Context
	onRead func()
}

func (b ctxBody) Read([]byte) (int, error) {
	b.onRead()
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (ctxBody) Close() error { return nil }

func TestExchangeContextEndsDuringBodyRead(t *testing.T) {
	for _, tt := range []struct {
		name string
		// cancelOnRead cancels the context from the body read. Otherwise the
		// read waits out the context's deadline on synctest's fake clock.
		cancelOnRead bool
		wantCode     codes.Code
	}{
		{"deadline", false, codes.DeadlineExceeded},
		{"cancel", true, codes.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				var read bool
				c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body: ctxBody{ctx: r.Context(), onRead: func() {
							read = true
							if tt.cancelOnRead {
								cancel()
							}
						}},
						Request: r,
					}, nil
				})}}
				_, err := c.Exchange(ctx, "https://sts.example/token", subjectToken, audience, nil)
				if got := status.Code(err); got != tt.wantCode {
					t.Errorf("Exchange error = %v (code %v), want code %v", err, got, tt.wantCode)
				}
				if !read {
					t.Error("Exchange did not read the response body")
				}
			})
		})
	}
}

func TestExchangeUnreachableEndpoint(t *testing.T) {
	srv, c := newTestServer(t, respond(http.StatusOK, `{"access_token":"at"}`))
	srv.Close()
	_, err := c.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil)
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("Exchange error = %v (code %v), want code %v", err, got, codes.Unavailable)
	}
}

func TestNewTrustsCAFile(t *testing.T) {
	srv, trusting := newTestServer(t, respond(http.StatusOK, `{"access_token":"at"}`))
	if _, err := trusting.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil); err != nil {
		t.Errorf("Exchange with the server's CA: %v", err)
	}

	systemOnly, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = systemOnly.Exchange(t.Context(), srv.URL+"/token", subjectToken, audience, nil)
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("Exchange without the server's CA: error = %v (code %v), want code %v", err, got, codes.Unavailable)
	}
}

func TestNewRejectsUnusableCAFile(t *testing.T) {
	noCerts := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(noCerts, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing file":        filepath.Join(t.TempDir(), "missing.pem"),
		"file without a cert": noCerts,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(path); err == nil {
				t.Errorf("New(%q) succeeded, want an error", path)
			}
		})
	}
}

func TestClipKeepsUTF8Valid(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   string
		want string
	}{{
		// "é" is 2 bytes, so after the 1-byte "x" the byte limit falls
		// inside a character, which clip must drop whole.
		name: "cut lands mid-character",
		in:   "x" + strings.Repeat("é", maxDetailBytes),
		want: "x" + strings.Repeat("é", (maxDetailBytes-1)/2),
	}, {
		name: "invalid bytes are replaced",
		in:   "bad \xff\xfe bytes",
		want: "bad \ufffd bytes",
	}} {
		t.Run(tt.name, func(t *testing.T) {
			got := clip(tt.in)
			if !utf8.ValidString(got) || len(got) > maxDetailBytes {
				t.Errorf("clip(%q) = %q (%d bytes), want valid UTF-8 within %d bytes", tt.in, got, len(got), maxDetailBytes)
			}
			if got != tt.want {
				t.Errorf("clip(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
