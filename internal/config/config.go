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
	"os"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const (
	// maxAudienceLen is MintActorJwtRequest's per-audience length limit.
	maxAudienceLen = 512
	// GCPSTSURL is the only token endpoint supported so far.
	GCPSTSURL = "https://sts.googleapis.com/v1/token"
)

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
	Name string `json:"name"`
	// TokenURL must be GCPSTSURL.
	TokenURL string `json:"tokenUrl"`
	// Audience is the RFC 8693 audience parameter and the aud of the minted
	// actor JWT: for Google Cloud, the workload identity pool provider's
	// resource name.
	Audience string   `json:"audience"`
	Scopes   []string `json:"scopes"`
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
	if p.TokenURL != GCPSTSURL {
		return fmt.Errorf("profile %q: tokenUrl %q must be %s", p.Name, p.TokenURL, GCPSTSURL)
	}
	if p.Audience == "" || len(p.Audience) > maxAudienceLen {
		return fmt.Errorf("profile %q: audience is required, at most %d bytes", p.Name, maxAudienceLen)
	}
	if len(p.Scopes) == 0 {
		return fmt.Errorf("profile %q: at least one scope is required", p.Name)
	}
	for _, s := range p.Scopes {
		if !isScopeToken(s) {
			return fmt.Errorf("profile %q: invalid scope %q", p.Name, s)
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
