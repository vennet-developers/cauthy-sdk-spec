package check

import (
	"context"
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
