package verify

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Config is what a backend tells its verifier.
type Config struct {
	// Issuer is Cauthy's issuer exactly as Cauthy writes it: https (http only
	// for localhost and 127.0.0.1), no trailing slash. The JWKS is fetched
	// from it.
	Issuer string
	// Issuers are further issuers a token may name, with the same format as
	// Issuer: the origin of a workspace's custom domain, for example. Their
	// keys are Issuer's; none of them is fetched. Empty by default.
	Issuers []string
	// Audience is the audience Cauthy's tokens carry for this deployment.
	Audience string
	// Tenant is the workspace's id. Required: a token of any other is refused.
	Tenant string
	// AllowAnonymous lets a guest's token through. Off by default.
	AllowAnonymous bool
	// Leeway is the clock tolerance: zero means DefaultLeeway; at most MaxLeeway.
	Leeway time.Duration
}

// Verifier checks tokens against one configuration and one key set.
type Verifier struct {
	cfg  Config
	keys Keys
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const nilUUID = "00000000-0000-0000-0000-000000000000"

// checkIssuer refuses an issuer that is not an https origin without a
// trailing slash, query or fragment (http only for localhost).
func checkIssuer(name, iss string) error {
	u, err := url.Parse(iss)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("verify: %s %q is not an absolute URL", name, iss)
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return fmt.Errorf("verify: %s %q must be https (http only for localhost)", name, iss)
	}
	if strings.HasSuffix(iss, "/") {
		return fmt.Errorf("verify: %s %q must not end in /", name, iss)
	}
	return nil
}

// New checks the configuration and answers a verifier. A configuration it
// refuses is an error at start, never a reason at request time.
func New(cfg Config, keys Keys) (*Verifier, error) {
	if err := checkIssuer("issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	for _, iss := range cfg.Issuers {
		if err := checkIssuer("issuers entry", iss); err != nil {
			return nil, err
		}
	}
	if cfg.Audience == "" {
		return nil, errors.New("verify: audience is required")
	}
	if !uuidRE.MatchString(cfg.Tenant) || cfg.Tenant == nilUUID {
		return nil, fmt.Errorf("verify: tenant %q is not a lowercase UUID", cfg.Tenant)
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = DefaultLeeway
	}
	if cfg.Leeway < 0 || cfg.Leeway > MaxLeeway {
		return nil, fmt.Errorf("verify: leeway %s is outside 0..%s", cfg.Leeway, MaxLeeway)
	}
	if keys == nil {
		return nil, errors.New("verify: keys are required")
	}
	return &Verifier{cfg: cfg, keys: keys}, nil
}
