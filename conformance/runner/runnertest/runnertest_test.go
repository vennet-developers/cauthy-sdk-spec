package runnertest_test

import (
	"context"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/runner"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/runner/runnertest"
)

// The backend follows a fake Cauthy, so a wrapper can test level switches.
func TestTheBackendPassesSwitchesAgainstItsCauthy(t *testing.T) {
	b := runnertest.NewStrictBackend()
	defer b.Close()
	c := b.StartCauthy("admin-token")
	out, err := runner.Run(context.Background(), runner.Options{Target: b.Target, Origin: b.URL, Email: b.Email, Password: b.Password,
		Level: runner.Switches, Cauthy: c.URL, Tenant: c.Tenant, AdminToken: "admin-token", ClientID: c.ClientID})
	if err != nil || !out.Passed || !out.Complete {
		t.Fatalf("%v\n%s", err, out.Text)
	}
}

// The backend runs on a CAUTHY_KEY its fake Cauthy issued, so a wrapper can
// test the key.* checks.
func TestTheBackendPassesTheKeyChecks(t *testing.T) {
	b := runnertest.NewStrictBackend()
	defer b.Close()
	c := b.StartCauthy("admin-token")
	key := b.IssueKey(c.URL)
	out, err := runner.Run(context.Background(), runner.Options{Target: b.Target, Origin: b.URL, Email: b.Email, Password: b.Password,
		Level: runner.Strict, Cauthy: c.URL, Tenant: c.Tenant, AdminToken: "admin-token", ClientID: c.ClientID, Key: key})
	if err != nil || !out.Passed || !out.Complete {
		t.Fatalf("%v\n%s", err, out.Text)
	}
	for _, id := range []string{"key.parses", "key.identity", "key.signs_in", "key.jwks"} {
		if !strings.Contains(out.Text, id) {
			t.Errorf("no %s in the report:\n%s", id, out.Text)
		}
	}
	if strings.Contains(out.Text, key) || strings.Contains(string(out.JSON), key) {
		t.Fatal("the report carries the key")
	}
}
