package checks

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

func TestTableChecks(t *testing.T) {
	reg := &check.Registry{}
	RegisterTable(reg)
	expect(t, reg, "table.every_route_answers", fake.Knobs{}, "pass")
	expect(t, reg, "table.methods_fields", fake.Knobs{}, "pass")
	expect(t, reg, "table.deprecated_still_answer", fake.Knobs{}, "pass")
}

// The fake has no knob for a missing route or a thin /methods, so these checks
// are proven to fail against a server that is wrong in exactly that way.
func TestTableChecksFailAgainstAWrongBackend(t *testing.T) {
	reg := &check.Registry{}
	RegisterTable(reg)
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/methods" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"providers":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer empty.Close()
	ctx, _ := ctxFor(t, fake.Knobs{})
	ctx.Client = client.New(empty.URL+"/api/auth", empty.URL)
	want := map[string]string{"table.every_route_answers": "fail", "table.methods_fields": "fail", "table.deprecated_still_answer": "fail"}
	for _, c := range reg.All() {
		if res := c.Run(ctx); res.Status != want[c.ID] {
			t.Errorf("%s: want %s, got %s (%s)", c.ID, want[c.ID], res.Status, res.Detail)
		}
	}
}
