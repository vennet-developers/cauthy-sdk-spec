package verify

import (
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

var goodConfig = Config{
	Issuer:   "https://auth.example.com",
	Audience: "cauthy",
	Tenant:   "8a6e0804-2bd0-4672-b79a-d97027f5f2a1",
}

func TestNewRefusesBadConfig(t *testing.T) {
	cases := map[string]func(*Config){
		"issuer missing":         func(c *Config) { c.Issuer = "" },
		"issuer http":            func(c *Config) { c.Issuer = "http://auth.example.com" },
		"issuer trailing slash":  func(c *Config) { c.Issuer = "https://auth.example.com/" },
		"issuer with query":      func(c *Config) { c.Issuer = "https://auth.example.com?x=1" },
		"issuers entry http":     func(c *Config) { c.Issuers = []string{"http://login.acme.example"} },
		"issuers entry slash":    func(c *Config) { c.Issuers = []string{"https://login.acme.example/"} },
		"issuers entry empty":    func(c *Config) { c.Issuers = []string{""} },
		"audience missing":       func(c *Config) { c.Audience = "" },
		"tenant missing":         func(c *Config) { c.Tenant = "" },
		"tenant upper case":      func(c *Config) { c.Tenant = strings.ToUpper(c.Tenant) },
		"tenant nil":             func(c *Config) { c.Tenant = "00000000-0000-0000-0000-000000000000" },
		"leeway negative":        func(c *Config) { c.Leeway = LeewayOf(-time.Second) },
		"leeway over 60 seconds": func(c *Config) { c.Leeway = LeewayOf(61 * time.Second) },
	}
	for name, change := range cases {
		cfg := goodConfig
		change(&cfg)
		if _, err := New(cfg, staticKeys()); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := New(goodConfig, nil); err == nil {
		t.Error("no keys: want an error")
	}
}

func TestNewAcceptsLocalhostOverHTTP(t *testing.T) {
	for _, iss := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://auth.localhost:8080", "http://cauthy.test", "https://auth.example.com"} {
		cfg := goodConfig
		cfg.Issuer = iss
		if _, err := New(cfg, staticKeys()); err != nil {
			t.Errorf("%s: %v", iss, err)
		}
	}
}

func TestNewAcceptsAListOfIssuers(t *testing.T) {
	cfg := goodConfig
	cfg.Issuers = []string{"https://login.acme.example", "http://localhost:3000"}
	if _, err := New(cfg, staticKeys()); err != nil {
		t.Fatal(err)
	}
}

func TestNewRefusesHTTPOnLookalikeHosts(t *testing.T) {
	for _, iss := range []string{"http://notlocalhost", "http://localhost.example.com", "http://attacker.test.example.com", "http://test"} {
		cfg := goodConfig
		cfg.Issuer = iss
		if _, err := New(cfg, staticKeys()); err == nil {
			t.Errorf("%s: want an error", iss)
		}
	}
}

func TestLeewayZeroIsConfigurable(t *testing.T) {
	v, err := New(Config{Issuer: goodConfig.Issuer, Audience: "cauthy", Tenant: goodConfig.Tenant, Leeway: LeewayOf(0)}, staticKeys())
	if err != nil {
		t.Fatal(err)
	}
	if v.leeway != 0 {
		t.Fatalf("an explicit zero leeway became %s", v.leeway)
	}
}

func TestJWKSURLIsDerivedFromTheIssuer(t *testing.T) {
	got, err := JWKSURL(goodConfig)
	if err != nil || got != "https://auth.example.com/.well-known/jwks.json" {
		t.Fatalf("got %q, %v", got, err)
	}
	cfg := goodConfig
	cfg.Issuer = "http://auth.example.com"
	if _, err := JWKSURL(cfg); err == nil {
		t.Error("http for a public host: want an error")
	}
	if _, err := NewRemote(cfg); err == nil {
		t.Error("NewRemote with http for a public host: want an error")
	}
	if r, err := NewRemote(goodConfig); err != nil || r == nil {
		t.Errorf("NewRemote: %v", err)
	}
}

func TestNewDefaultsTheLeeway(t *testing.T) {
	v, err := New(goodConfig, staticKeys())
	if err != nil {
		t.Fatal(err)
	}
	if v.leeway != DefaultLeeway {
		t.Fatalf("leeway %s, want %s", v.leeway, DefaultLeeway)
	}
}

func staticKeys() *StaticKeys { return &StaticKeys{byKid: map[string]*rsa.PublicKey{}} }
