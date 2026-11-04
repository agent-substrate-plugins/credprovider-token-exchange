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

// Package config loads and validates the provider's token exchange profiles
// and the atespace→profile policy.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

// maxAudienceLen is MintActorJwtRequest's per-audience length limit.
const maxAudienceLen = 512

// Config is the provider's configuration file.
type Config struct {
	// ProviderName is the host of the ate-secret:// URIs this provider serves.
	ProviderName string    `json:"providerName"`
	Profiles     []Profile `json:"profiles"`
	Policy       Policy    `json:"policy"`

	profiles map[string]*Profile
	allowed  map[string]map[string]bool
}

// Profile is one RFC 8693 token exchange an actor may be granted.
type Profile struct {
	Name     string `json:"name"`
	TokenURL string `json:"tokenUrl"`
	// Audience is the RFC 8693 audience parameter, omitted if empty.
	Audience string `json:"audience,omitempty"`
	// SubjectTokenAudience is the aud of the minted actor JWT. Defaults to
	// Audience; at least one of the two is required.
	SubjectTokenAudience string `json:"subjectTokenAudience,omitempty"`
	// Scopes is the RFC 8693 scope parameter, omitted if empty.
	Scopes []string `json:"scopes,omitempty"`
}

// Policy grants profiles to atespaces. Anything not listed is denied.
type Policy struct {
	Atespaces map[string][]string `json:"atespaces"`
}

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes and validates a config, rejecting unknown fields.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("decoding config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	var errs []error
	if len(validation.IsDNS1123Subdomain(c.ProviderName)) != 0 {
		errs = append(errs, fmt.Errorf("providerName %q must be a lowercase DNS-1123 subdomain", c.ProviderName))
	}
	if len(c.Profiles) == 0 {
		errs = append(errs, errors.New("at least one profile is required"))
	}
	c.profiles = make(map[string]*Profile, len(c.Profiles))
	for i := range c.Profiles {
		p := &c.Profiles[i]
		if err := p.validate(); err != nil {
			errs = append(errs, fmt.Errorf("profiles[%d]: %w", i, err))
			continue
		}
		if _, dup := c.profiles[p.Name]; dup {
			errs = append(errs, fmt.Errorf("profiles[%d]: duplicate name %q", i, p.Name))
			continue
		}
		c.profiles[p.Name] = p
	}
	c.allowed = make(map[string]map[string]bool, len(c.Policy.Atespaces))
	for atespace, names := range c.Policy.Atespaces {
		if len(validation.IsDNS1123Label(atespace)) != 0 {
			errs = append(errs, fmt.Errorf("policy.atespaces: %q is not a valid atespace name", atespace))
		}
		granted := make(map[string]bool, len(names))
		for _, n := range names {
			if _, ok := c.profiles[n]; !ok {
				errs = append(errs, fmt.Errorf("policy.atespaces[%s]: unknown profile %q", atespace, n))
			}
			granted[n] = true
		}
		c.allowed[atespace] = granted
	}
	return errors.Join(errs...)
}

func (p *Profile) validate() error {
	if len(validation.IsDNS1123Label(p.Name)) != 0 {
		return fmt.Errorf("name %q must be a DNS label", p.Name)
	}
	if err := validateTokenURL(p.TokenURL); err != nil {
		return fmt.Errorf("profile %q: tokenUrl %q: %w", p.Name, p.TokenURL, err)
	}
	if len(p.Audience) > maxAudienceLen {
		return fmt.Errorf("profile %q: audience exceeds %d bytes", p.Name, maxAudienceLen)
	}
	if p.SubjectTokenAudience == "" {
		p.SubjectTokenAudience = p.Audience
	}
	if p.SubjectTokenAudience == "" {
		return fmt.Errorf("profile %q: audience or subjectTokenAudience is required", p.Name)
	}
	if len(p.SubjectTokenAudience) > maxAudienceLen {
		return fmt.Errorf("profile %q: subjectTokenAudience exceeds %d bytes", p.Name, maxAudienceLen)
	}
	for _, s := range p.Scopes {
		if !isScopeToken(s) {
			return fmt.Errorf("profile %q: invalid scope %q", p.Name, s)
		}
	}
	return nil
}

func validateTokenURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return err
	case u.Scheme != "https":
		return errors.New("must be an https URL")
	case u.User != nil, u.RawQuery != "", u.ForceQuery, u.Fragment != "", strings.Contains(raw, "#"):
		return errors.New("must not have user information, a query or a fragment")
	case len(validation.IsDNS1123Subdomain(u.Hostname())) != 0:
		return errors.New("host must be a lowercase DNS-1123 subdomain")
	case strings.HasSuffix(u.Host, ":"):
		return errors.New("port must not be empty")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid port %q", port)
		}
	}
	return nil
}

// isScopeToken reports whether s is an RFC 6749 section 3.3 scope-token:
// printable ASCII other than space, '"' and '\'.
func isScopeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < '!' || c > '~' || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// Profile returns the named profile.
func (c *Config) Profile(name string) (*Profile, bool) {
	p, ok := c.profiles[name]
	return p, ok
}

// Allowed reports whether the policy grants profile to atespace.
func (c *Config) Allowed(atespace, profile string) bool {
	return c.allowed[atespace][profile]
}
