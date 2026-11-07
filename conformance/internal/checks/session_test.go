package checks

import (
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

func sessionRegistry() *check.Registry {
	reg := &check.Registry{}
	RegisterSession(reg)
	return reg
}

func TestSessionChecks(t *testing.T) {
	reg := sessionRegistry()
	expect(t, reg, "session.unauthenticated_shape", fake.Knobs{}, "pass")
	expect(t, reg, "session.sign_in_email", fake.Knobs{}, "pass")
	expect(t, reg, "session.cookie_attributes", fake.Knobs{}, "pass")
	expect(t, reg, "session.cookie_attributes", fake.Knobs{NoHttpOnly: true}, "fail")
	expect(t, reg, "session.cookie_attributes", fake.Knobs{NoSameSite: true}, "fail")
	expect(t, reg, "session.authenticated_shape", fake.Knobs{}, "pass")
	expect(t, reg, "session.short_by_default", fake.Knobs{}, "pass")
	expect(t, reg, "session.remember_needs_tenant", fake.Knobs{}, "pass")
	expect(t, reg, "session.remember_needs_tenant", fake.Knobs{RememberIgnoresTenant: true}, "fail")
	expect(t, reg, "session.remember_when_allowed", fake.Knobs{PersistentAllowed: true}, "pass")
	expect(t, reg, "session.remember_when_allowed", fake.Knobs{}, "n/a")
	expect(t, reg, "session.sign_out", fake.Knobs{}, "pass")
}

func TestSessionChecksSkipWithoutCredentials(t *testing.T) {
	ctx, _ := ctxFor(t, fake.Knobs{})
	ctx.Email, ctx.Password = "", ""
	for _, c := range sessionRegistry().All() {
		switch c.ID {
		case "session.sign_in_email", "session.cookie_attributes", "session.authenticated_shape", "session.short_by_default", "session.sign_out":
			if res := c.Run(ctx); res.Status != "skip" {
				t.Errorf("%s without credentials: %s", c.ID, res.Status)
			}
		}
	}
}

func TestSessionChecksFailWhenSignInIsBroken(t *testing.T) {
	reg := sessionRegistry()
	for _, id := range []string{"session.sign_in_email", "session.cookie_attributes", "session.authenticated_shape", "session.short_by_default", "session.remember_needs_tenant", "session.sign_out"} {
		expect(t, reg, id, fake.Knobs{SignInBroken: true}, "fail")
	}
	expect(t, reg, "session.remember_when_allowed", fake.Knobs{SignInBroken: true, PersistentAllowed: true}, "fail")
}

func TestSessionChecksSkipWhenTheAccountNeedsMFA(t *testing.T) {
	reg := sessionRegistry()
	for _, id := range []string{"session.sign_in_email", "session.cookie_attributes", "session.authenticated_shape", "session.short_by_default", "session.remember_needs_tenant", "session.sign_out"} {
		expect(t, reg, id, fake.Knobs{MFARequired: true}, "skip")
	}
}

func TestSessionChecksFailWhenRateLimited(t *testing.T) {
	ctx, _ := ctxFor(t, fake.Knobs{RateLimited: true})
	reg := sessionRegistry()
	RegisterErrors(reg)
	for _, c := range reg.All() {
		if c.ID != "session.sign_in_email" && c.ID != "errors.wrong_password_is_not_200" {
			continue
		}
		res := c.Run(ctx)
		if res.Status != "fail" || !strings.Contains(res.Detail, "rate limited") {
			t.Fatalf("%s on a 429: %s %s", c.ID, res.Status, res.Detail)
		}
	}
}

func TestARunSignsInAtMostThreeTimesAndLeavesNoSession(t *testing.T) {
	ctx, srv := ctxFor(t, fake.Knobs{Strict: true, PersistentAllowed: true})
	reg := &check.Registry{}
	RegisterAll(reg)
	rep := reg.Run(ctx, check.Strict)
	if !rep.Passed() {
		t.Fatalf("the default strict fake must pass:\n%s", rep.Text())
	}
	if n := srv.SignIns(); n > 3 {
		t.Errorf("a run opened %d sessions, want at most 3", n)
	}
	if n := srv.OpenSessions(); n != 0 {
		t.Errorf("a run left %d sessions open", n)
	}
}

func TestCookieAttributeProofs(t *testing.T) {
	reg := sessionRegistry()
	expect(t, reg, "session.cookie_attributes", fake.Knobs{CookiePathWrong: true}, "fail")
}

// httpsRun runs one check against a fake that trusts an https application origin.
func httpsRun(t *testing.T, reg *check.Registry, id string, k fake.Knobs) check.Result {
	t.Helper()
	ctx, srv := ctxFor(t, k)
	srv.SetAppOrigin("https://app.example")
	ctx.Client = client.New(srv.Target(), "https://app.example")
	for _, c := range reg.All() {
		if c.ID == id {
			return c.Run(ctx)
		}
	}
	t.Fatalf("no check %s", id)
	return check.Result{}
}

func TestSecureIsRequiredOnAnHTTPSOrigin(t *testing.T) {
	reg := sessionRegistry()
	if r := httpsRun(t, reg, "session.cookie_attributes", fake.Knobs{}); r.Status != "pass" {
		t.Fatalf("a Secure cookie on https: %s %s", r.Status, r.Detail)
	}
	if r := httpsRun(t, reg, "session.cookie_attributes", fake.Knobs{NoSecure: true}); r.Status != "fail" {
		t.Fatalf("no Secure on https must fail: %s %s", r.Status, r.Detail)
	}
}
