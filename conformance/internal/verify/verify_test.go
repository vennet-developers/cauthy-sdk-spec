package verify

import (
	"context"
	"crypto/rsa"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/jws"
)

var now = time.Unix(1767225600, 0)

func verifier(t *testing.T, change func(*Config)) *Verifier {
	t.Helper()
	strong, _ := keys(t)
	cfg := goodConfig
	if change != nil {
		change(&cfg)
	}
	v, err := New(cfg, &StaticKeys{byKid: map[string]*rsa.PublicKey{"k": &strong.PublicKey}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func token(t *testing.T, claims map[string]any) string {
	t.Helper()
	strong, _ := keys(t)
	base := map[string]any{
		"iss": goodConfig.Issuer, "aud": []string{goodConfig.Audience}, "tid": goodConfig.Tenant,
		"sub": "5c1b2f4e-9a3d-4b7e-8c6f-0d1e2f3a4b5c", "iat": now.Unix() - 60, "exp": now.Unix() + 840,
		"email": "ada@example.com", "roles": []string{"member", "billing"},
	}
	for k, v := range claims { // a nil value removes the claim
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	return jws.RS256(strong, map[string]any{"alg": "RS256", "kid": "k", "typ": "JWT"}, base)
}

func reasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func TestVerifyAnswersWhoTheTokenIsFor(t *testing.T) {
	id, err := verifier(t, nil).Verify(context.Background(), token(t, nil), now)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "5c1b2f4e-9a3d-4b7e-8c6f-0d1e2f3a4b5c" || id.Tenant != goodConfig.Tenant || id.Email != "ada@example.com" ||
		!slices.Equal(id.Roles, []string{"member", "billing"}) || id.Anonymous || !id.ExpiresAt.Equal(now.Add(840*time.Second)) {
		t.Fatalf("identity: %+v", id)
	}
}

func TestVerifyUsesTheConfiguredLeeway(t *testing.T) {
	tok := token(t, map[string]any{"exp": now.Unix() - 10})
	if _, err := verifier(t, nil).Verify(context.Background(), tok, now); err != nil {
		t.Fatalf("default leeway: %v", err)
	}
	strict := verifier(t, func(c *Config) { c.Leeway = LeewayOf(5 * time.Second) })
	if _, err := strict.Verify(context.Background(), tok, now); reasonOf(err) != Expired {
		t.Fatalf("5s leeway: want expired, got %v", err)
	}
}

func TestVerifyAllowsGuestsOnlyWhenTold(t *testing.T) {
	tok := token(t, map[string]any{"anon": true, "email": nil})
	if _, err := verifier(t, nil).Verify(context.Background(), tok, now); reasonOf(err) != AnonymousToken {
		t.Fatalf("want anonymous_token, got %v", err)
	}
	id, err := verifier(t, func(c *Config) { c.AllowAnonymous = true }).Verify(context.Background(), tok, now)
	if err != nil || !id.Anonymous {
		t.Fatalf("allowed: %+v, %v", id, err)
	}
}

func TestVerifyAcceptsEveryListedIssuerAndNoOther(t *testing.T) {
	const custom = "https://login.acme.example"
	listed := verifier(t, func(c *Config) { c.Issuers = []string{custom} })
	for _, iss := range []string{goodConfig.Issuer, custom} {
		if _, err := listed.Verify(context.Background(), token(t, map[string]any{"iss": iss}), now); err != nil {
			t.Errorf("%s: %v", iss, err)
		}
	}
	for _, iss := range []string{custom + "/", "https://Login.acme.example", "https://attacker.example.com"} {
		if _, err := listed.Verify(context.Background(), token(t, map[string]any{"iss": iss}), now); reasonOf(err) != WrongIssuer {
			t.Errorf("%s: want wrong_issuer, got %v", iss, err)
		}
	}
	if _, err := verifier(t, nil).Verify(context.Background(), token(t, map[string]any{"iss": custom}), now); reasonOf(err) != WrongIssuer {
		t.Errorf("unlisted: want wrong_issuer, got %v", err)
	}
}

func TestRefusalNeverQuotesTheToken(t *testing.T) {
	tok := token(t, map[string]any{"tid": "3f2a9c41-7d4b-4e8a-a1c2-5b6d7e8f9a0b"})
	_, err := verifier(t, nil).Verify(context.Background(), tok, now)
	if reasonOf(err) != WrongTenant {
		t.Fatalf("want wrong_tenant, got %v", err)
	}
	if strings.Contains(err.Error(), strings.Split(tok, ".")[2]) {
		t.Fatal("the error quotes the token")
	}
}

func TestVerifyWithNoLeewayAtAll(t *testing.T) {
	none := verifier(t, func(c *Config) { c.Leeway = LeewayOf(0) })
	if _, err := none.Verify(context.Background(), token(t, map[string]any{"exp": now.Unix() + 1}), now); err != nil {
		t.Fatalf("one second left: %v", err)
	}
	if _, err := none.Verify(context.Background(), token(t, map[string]any{"exp": now.Unix()}), now); reasonOf(err) != Expired {
		t.Fatalf("exp is now: want expired, got %v", err)
	}
}

func TestVerifyReportsEmailVerified(t *testing.T) {
	id, err := verifier(t, nil).Verify(context.Background(), token(t, map[string]any{"email_verified": true}), now)
	if err != nil || !id.EmailVerified {
		t.Fatalf("%+v, %v", id, err)
	}
	id, err = verifier(t, nil).Verify(context.Background(), token(t, nil), now)
	if err != nil || id.EmailVerified {
		t.Fatalf("absent must read false: %+v, %v", id, err)
	}
}
