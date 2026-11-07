package checks

import (
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

func TestStrictChecks(t *testing.T) {
	reg := &check.Registry{}
	RegisterStrict(reg)
	expect(t, reg, "strict.protocol_header", fake.Knobs{Strict: true}, "pass")
	expect(t, reg, "strict.protocol_header", fake.Knobs{}, "fail")
	expect(t, reg, "strict.request_header_required", fake.Knobs{Strict: true}, "pass")
	expect(t, reg, "strict.request_header_required", fake.Knobs{}, "fail")
	expect(t, reg, "strict.next_on_sign_in", fake.Knobs{Strict: true}, "pass")
	expect(t, reg, "strict.next_on_sign_in", fake.Knobs{}, "fail")
}

func TestAllRegistersEveryGroup(t *testing.T) {
	reg := &check.Registry{}
	RegisterAll(reg)
	groups := map[string]bool{}
	for _, c := range reg.All() {
		groups[c.Group] = true
	}
	for _, g := range []string{"protocol", "session", "errors", "csrf", "table", "strict"} {
		if !groups[g] {
			t.Errorf("group %s not registered", g)
		}
	}
}
