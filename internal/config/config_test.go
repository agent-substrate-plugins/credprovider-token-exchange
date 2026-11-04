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
  subjectTokenAudience: https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/q
  scopes: ["https://www.googleapis.com/auth/cloud-platform"]
- name: other
  tokenUrl: https://sts.example.com/token
  audience: https://api.example.com
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
	p, ok := c.Profile("gcp")
	if !ok {
		t.Fatal("profile gcp not found")
	}
	if want := "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/q"; p.SubjectTokenAudience != want {
		t.Errorf("explicit SubjectTokenAudience = %q, want %q", p.SubjectTokenAudience, want)
	}
	p, _ = c.Profile("other")
	if p.SubjectTokenAudience != "https://api.example.com" {
		t.Errorf("default SubjectTokenAudience = %q, want the audience", p.SubjectTokenAudience)
	}
	if len(p.Scopes) != 0 {
		t.Errorf("Scopes = %q, want none", p.Scopes)
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

func TestParseSubjectTokenAudienceOnly(t *testing.T) {
	c, err := Parse([]byte(strings.Replace(valid, "  audience: https://api.example.com", "  subjectTokenAudience: https://sts.example.com", 1)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p, _ := c.Profile("other"); p.Audience != "" || p.SubjectTokenAudience != "https://sts.example.com" {
		t.Errorf("got Audience %q, SubjectTokenAudience %q", p.Audience, p.SubjectTokenAudience)
	}
}

func TestParseInvalid(t *testing.T) {
	for name, tc := range map[string]struct {
		from, to, wantErr string
	}{
		"unknown field":          {"providerName:", "bogus: 1\nproviderName:", "unknown field"},
		"removed serviceAccount": {"  audience: https://api.example.com", "  audience: https://api.example.com\n  serviceAccount: sa@p.iam.gserviceaccount.com", "unknown field"},
		"empty provider":         {"providerName: token-exchange", "providerName: ''", "providerName"},
		"provider with path":     {"providerName: token-exchange", "providerName: a/b", "providerName"},
		"http token url":         {"tokenUrl: https://sts.example.com", "tokenUrl: http://sts.example.com", "https URL"},
		"bad profile name":       {"- name: gcp\n", "- name: GCP\n", "DNS label"},
		"duplicate profile":      {"- name: other", "- name: gcp", "duplicate"},
		"unknown policy ref":     {`team-b: ["gcp"]`, `team-b: ["nope"]`, "unknown profile"},
		"bad atespace":           {"team-b:", "Team_B:", "atespace"},
		"no audience":            {"  audience: https://api.example.com\n", "", "audience or subjectTokenAudience"},
		"bad scope":              {`scopes: ["https://www.googleapis.com/auth/cloud-platform"]`, `scopes: ["a b"]`, "invalid scope"},
		"long audience":          {"  audience: https://api.example.com", "  audience: https://" + strings.Repeat("a", 600), "audience exceeds"},
		"long subject audience":  {"  audience: https://api.example.com", "  subjectTokenAudience: https://" + strings.Repeat("a", 600), "subjectTokenAudience exceeds"},
		"uppercase provider":     {"providerName: token-exchange", "providerName: Token-Exchange", "providerName"},
		"provider with port":     {"providerName: token-exchange", "providerName: sts:443", "providerName"},
		"token url no host":      {"tokenUrl: https://sts.example.com/token", "tokenUrl: https://:443/token", "DNS-1123"},
		"token url uppercase":    {"tokenUrl: https://sts.example.com/token", "tokenUrl: https://STS.example.com/token", "DNS-1123"},
		"token url query":        {"tokenUrl: https://sts.example.com/token", "tokenUrl: https://sts.example.com/token?a=b", "query"},
		"token url empty query":  {"tokenUrl: https://sts.example.com/token", "tokenUrl: https://sts.example.com/token?", "query"},
		"token url fragment":     {"tokenUrl: https://sts.example.com/token", "tokenUrl: 'https://sts.example.com/token#'", "fragment"},
		"token url user":         {"tokenUrl: https://sts.example.com/token", "tokenUrl: https://u@sts.example.com/token", "user"},
		"token url port 0":       {"tokenUrl: https://sts.example.com/token", "tokenUrl: https://sts.example.com:0/token", "port"},
		"token url big port":     {"tokenUrl: https://sts.example.com/token", "tokenUrl: https://sts.example.com:99999/token", "port"},
		"token url empty port":   {"tokenUrl: https://sts.example.com/token", "tokenUrl: https://sts.example.com:/token", "port"},
		"scope with quote":       {`scopes: ["https://www.googleapis.com/auth/cloud-platform"]`, `scopes: ['a"b']`, "invalid scope"},
		"scope with backslash":   {`scopes: ["https://www.googleapis.com/auth/cloud-platform"]`, `scopes: ['a\b']`, "invalid scope"},
		"empty scope":            {`scopes: ["https://www.googleapis.com/auth/cloud-platform"]`, `scopes: [""]`, "invalid scope"},
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

func TestParseAcceptsPort(t *testing.T) {
	if _, err := Parse([]byte(strings.Replace(valid, "tokenUrl: https://sts.example.com/token", "tokenUrl: https://sts.example.com:8443/token", 1))); err != nil {
		t.Errorf("Parse: %v", err)
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
