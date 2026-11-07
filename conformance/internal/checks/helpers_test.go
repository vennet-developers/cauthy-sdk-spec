package checks

import (
	"path/filepath"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

func ctxFor(t *testing.T, k fake.Knobs) (*check.Ctx, *fake.Server) {
	t.Helper()
	srv := fake.New(k)
	t.Cleanup(srv.Close)
	table, err := routes.Load(filepath.Join("..", "..", "..", "protocol", "routes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return &check.Ctx{Client: client.New(srv.Target(), srv.URL), Table: table, Email: srv.Email, Password: srv.Password}, srv
}

// expect runs one check by id against the knobs and asserts its status.
func expect(t *testing.T, reg *check.Registry, id string, k fake.Knobs, status string) {
	t.Helper()
	ctx, _ := ctxFor(t, k)
	for _, c := range reg.All() {
		if c.ID != id {
			continue
		}
		res := c.Run(ctx)
		if res.Status != status {
			t.Fatalf("%s with %+v: want %s, got %s (%s)", id, k, status, res.Status, res.Detail)
		}
		return
	}
	t.Fatalf("no check %s", id)
}
