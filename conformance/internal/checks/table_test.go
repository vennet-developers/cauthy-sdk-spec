package checks

import (
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

func TestTableChecks(t *testing.T) {
	reg := &check.Registry{}
	RegisterTable(reg)
	expect(t, reg, "table.every_route_answers", fake.Knobs{}, "pass")
	expect(t, reg, "table.methods_fields", fake.Knobs{}, "pass")
	expect(t, reg, "table.deprecated_still_answer", fake.Knobs{}, "pass")
}
