package check

import (
	"context"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/admin"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

// A run stopped half way still leaves the tenant as it found it.
func TestCleanupPutsTheTenantBack(t *testing.T) {
	srv := fake.New(fake.Knobs{})
	defer srv.Close()
	base := srv.StartCauthy("admin-token")
	c := &Ctx{Client: client.New(srv.Target(), srv.URL), Admin: admin.New(context.Background(), base, fake.Tenant, "admin-token", fake.ClientID)}
	if err := c.Admin.Set(map[string]any{"allow_signup": false}); err != nil {
		t.Fatal(err)
	}
	if err := c.Admin.SetPersistent(true); err != nil {
		t.Fatal(err)
	}
	c.Cleanup()
	if srv.Setting("allow_signup") != true || srv.ClientPersistent() {
		t.Fatalf("not put back: allow_signup=%v persistent=%v", srv.Setting("allow_signup"), srv.ClientPersistent())
	}
	c.Cleanup() // twice is safe
}

// A tenant the run could not put back fails the run, by name.
func TestRunReportsATenantLeftChanged(t *testing.T) {
	srv := fake.New(fake.Knobs{})
	defer srv.Close()
	base := srv.StartCauthy("admin-token")
	c := &Ctx{Client: client.New(srv.Target(), srv.URL), Admin: admin.New(context.Background(), base, fake.Tenant, "admin-token", fake.ClientID)}
	reg := &Registry{}
	reg.Add(Check{ID: "changes", Group: "switches", Level: Basic, Run: func(c *Ctx) Result {
		if err := c.Admin.Set(map[string]any{"allow_signup": false}); err != nil {
			return Fail(err.Error())
		}
		srv.CloseCauthy() // Cauthy goes away before the run can put it back
		return Pass("")
	}})
	rep := reg.Run(c, Basic)
	if rep.Passed() {
		t.Fatalf("a tenant left changed must fail the run: %+v", rep.Results)
	}
	last := rep.Results[len(rep.Results)-1]
	if last.ID != "cleanup" || !strings.Contains(last.Detail, "tenant") {
		t.Fatalf("want a cleanup failure, got %+v", last)
	}
}
