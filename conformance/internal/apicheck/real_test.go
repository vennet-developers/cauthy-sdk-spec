package apicheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/oas"
)

// Inputs are the variables openapi/probes.yaml expects a run to set.
var Inputs = []string{"member_email", "member_password", "owner_email", "owner_password", "system", "client_id", "client_secret", "origin"}

// The real probes send every operation of the real document, name only
// operations it has, and use no variable before something sets it.
func TestTheRealProbesCoverTheRealDocument(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "cauthy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := oas.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	rawProbes, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "probes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(rawProbes)
	if err != nil {
		t.Fatal(err)
	}
	uncovered, unknown := Coverage(doc, f)
	if len(uncovered) > 0 {
		t.Errorf("no probe sends:\n  %s", strings.Join(uncovered, "\n  "))
	}
	if len(unknown) > 0 {
		t.Errorf("probes name operations the document lacks:\n  %s", strings.Join(unknown, "\n  "))
	}
	if unset := Unset(f, Inputs); len(unset) > 0 {
		t.Errorf("%s", strings.Join(unset, "\n"))
	}
}
