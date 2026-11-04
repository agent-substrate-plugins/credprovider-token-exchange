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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `
providerName: token-exchange
profiles:
- name: gcp
  tokenUrl: https://sts.googleapis.com/v1/token
  audience: //iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/q
  scopes: ["https://www.googleapis.com/auth/cloud-platform"]
- name: other
  tokenUrl: https://sts.googleapis.com/v1/token
  audience: //iam.googleapis.com/projects/456/locations/global/workloadIdentityPools/p/providers/q
  scopes: ["https://www.googleapis.com/auth/devstorage.read_only"]
policy:
  atespaces:
    team-a: ["gcp", "other"]
    team-b: ["gcp"]
`

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := c.Profile("gcp"); !ok {
		t.Fatal("profile gcp not found")
	}
	for _, tc := range []struct {
		atespace, profile string
		want              bool
	}{
		{"team-a", "gcp", true},
		{"team-a", "other", true},
		{"team-b", "gcp", true},
		{"team-b", "other", false},
		{"team-c", "gcp", false},
	} {
		if got := c.Allowed(tc.atespace, tc.profile); got != tc.want {
			t.Errorf("Allowed(%q, %q) = %v, want %v", tc.atespace, tc.profile, got, tc.want)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	const otherAudience = "  audience: //iam.googleapis.com/projects/456/locations/global/workloadIdentityPools/p/providers/q"
	const otherScopes = `scopes: ["https://www.googleapis.com/auth/devstorage.read_only"]`
	for name, tc := range map[string]struct {
		from, to, wantErr string
	}{
		"unknown field":        {"providerName:", "bogus: 1\nproviderName:", "unknown field"},
		"empty provider":       {"providerName: token-exchange", "providerName: ''", "providerName"},
		"provider with path":   {"providerName: token-exchange", "providerName: a/b", "providerName"},
		"uppercase provider":   {"providerName: token-exchange", "providerName: Token-Exchange", "providerName"},
		"provider with port":   {"providerName: token-exchange", "providerName: sts:443", "providerName"},
		"other token url":      {"- name: other\n  tokenUrl: https://sts.googleapis.com/v1/token", "- name: other\n  tokenUrl: https://sts.example.com/token", "must be https://sts.googleapis.com/v1/token"},
		"bad profile name":     {"- name: gcp\n", "- name: GCP\n", "DNS label"},
		"duplicate profile":    {"- name: other", "- name: gcp", "duplicate"},
		"unknown policy ref":   {`team-b: ["gcp"]`, `team-b: ["nope"]`, "unknown profile"},
		"bad atespace":         {"team-b:", "Team_B:", "atespace"},
		"no audience":          {otherAudience + "\n", "", "audience is required"},
		"long audience":        {otherAudience, "  audience: //" + strings.Repeat("a", 600), "audience is required"},
		"no scopes":            {otherScopes, "scopes: []", "at least one scope"},
		"scope with space":     {otherScopes, `scopes: ["a b"]`, "invalid scope"},
		"scope with quote":     {otherScopes, `scopes: ['a"b']`, "invalid scope"},
		"scope with backslash": {otherScopes, `scopes: ['a\b']`, "invalid scope"},
		"empty scope":          {otherScopes, `scopes: [""]`, "invalid scope"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(valid, tc.from) {
				t.Fatalf("test bug: %q not in valid config", tc.from)
			}
			_, err := Parse([]byte(strings.Replace(valid, tc.from, tc.to, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Parse error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseRequiresProfiles(t *testing.T) {
	if _, err := Parse([]byte("providerName: x\n")); err == nil {
		t.Error("Parse accepted a config without profiles")
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("Load: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("Load accepted a missing file")
	}
}
