package checks

import (
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

func TestErrorAndCSRFChecks(t *testing.T) {
	reg := &check.Registry{}
	RegisterErrors(reg)
	RegisterCSRF(reg)
	expect(t, reg, "errors.not_json_is_bad_request", fake.Knobs{}, "pass")
	expect(t, reg, "errors.not_json_is_bad_request", fake.Knobs{LenientJSON: true}, "fail")
	expect(t, reg, "errors.validation_names_field", fake.Knobs{NoErrorField: true}, "fail")
	expect(t, reg, "errors.shape", fake.Knobs{}, "pass")
	expect(t, reg, "errors.shape", fake.Knobs{ErrorFlat: true}, "fail")
	expect(t, reg, "errors.validation_names_field", fake.Knobs{}, "pass")
	expect(t, reg, "errors.wrong_password_is_not_200", fake.Knobs{}, "pass")
	expect(t, reg, "errors.auth_route_401", fake.Knobs{}, "pass")
	expect(t, reg, "errors.auth_route_401", fake.Knobs{NoAuth401: true}, "fail")
	expect(t, reg, "csrf.foreign_origin_403", fake.Knobs{}, "pass")
	expect(t, reg, "csrf.foreign_origin_403", fake.Knobs{AcceptCrossSite: true}, "fail")
	expect(t, reg, "csrf.sign_out_foreign_origin_403", fake.Knobs{}, "pass")
	expect(t, reg, "csrf.sign_out_foreign_origin_403", fake.Knobs{AcceptCrossSite: true}, "fail")
	expect(t, reg, "csrf.fetch_site_same_site_403", fake.Knobs{}, "pass")
	expect(t, reg, "csrf.fetch_site_same_site_403", fake.Knobs{AcceptCrossSite: true}, "fail")
	expect(t, reg, "csrf.fetch_site_cross_403", fake.Knobs{}, "pass")
	expect(t, reg, "csrf.fetch_site_cross_403", fake.Knobs{AcceptCrossSite: true}, "fail")
}
