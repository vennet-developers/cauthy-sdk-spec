package checks

import (
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
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
	expect(t, reg, "session.remember_when_allowed", fake.Knobs{}, "skip")
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
