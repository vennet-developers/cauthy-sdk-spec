package runnertest_test

import (
	"context"
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
