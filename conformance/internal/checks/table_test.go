package checks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

type seen struct{ method, path, body string }

// recorder answers like a backend that serves the table, and remembers what it was asked.
func recorder(t *testing.T, providers string) (*httptest.Server, *[]seen) {
	var mu sync.Mutex
	var log []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		log = append(log, seen{r.Method, r.URL.Path, string(raw)})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/auth/methods":
			w.Write([]byte(`{"providers":` + providers + `}`))
		case r.Method == "POST":
			w.WriteHeader(400)
			w.Write([]byte(`{"error":{"code":"bad_request","message":"no"}}`))
		default:
			w.WriteHeader(401)
			w.Write([]byte(`{"error":{"code":"unauthenticated","message":"no"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &log
}

func TestTableProbeSendsAnArrayAndUsesAnEnabledProvider(t *testing.T) {
	srv, log := recorder(t, `[{"id":"github"}]`)
	ctx, _ := ctxFor(t, fake.Knobs{})
	ctx.Client = client.New(srv.URL+"/api/auth", srv.URL)
	reg := &check.Registry{}
	RegisterTable(reg)
	for _, c := range reg.All() {
		if c.ID == "table.every_route_answers" {
			if res := c.Run(ctx); res.Status != "pass" {
				t.Fatalf("%s %s", res.Status, res.Detail)
			}
		}
	}
	posts, social := 0, 0
	for _, s := range *log {
		if s.method == "POST" && s.path != "/api/auth/logout" {
			posts++
			if s.body != "[]" && s.body != "{}" {
				t.Errorf("POST %s sent %q", s.path, s.body)
			}
		}
		if strings.Contains(s.path, "/sign-in/social/") {
			social++
			if !strings.HasSuffix(s.path, "/github") {
				t.Errorf("provider probe used %s, want the first enabled provider", s.path)
			}
		}
	}
	if posts == 0 || social == 0 {
		t.Fatalf("probed %d POSTs and %d social routes", posts, social)
	}
	for _, s := range *log {
		if s.method != "POST" {
			continue
		}
		for _, rt := range ctx.Table.Routes {
			if rt.Method == "POST" && rt.Path == strings.TrimPrefix(s.path, "/api/auth") && rt.Needs("json") && s.body != "[]" {
				t.Errorf("json route %s got %q, want []", rt.ID, s.body)
			}
		}
	}
}

func TestTableProbeFallsBackToGoogleWithNoProviders(t *testing.T) {
	srv, log := recorder(t, `[]`)
	ctx, _ := ctxFor(t, fake.Knobs{})
	ctx.Client = client.New(srv.URL+"/api/auth", srv.URL)
	reg := &check.Registry{}
	RegisterTable(reg)
	reg.All()[0].Run(ctx)
	for _, s := range *log {
		if strings.Contains(s.path, "/sign-in/social/") && !strings.HasSuffix(s.path, "/google") {
			t.Errorf("fallback provider: %s", s.path)
		}
	}
}

func TestTableCountsAJSON404AsServedButNotAPlainOne(t *testing.T) {
	json404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/auth/methods" {
			w.Write([]byte(`{"providers":[]}`))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte(`{"error":{"code":"invalid_provider","message":"no"}}`))
	}))
	defer json404.Close()
	ctx, _ := ctxFor(t, fake.Knobs{})
	ctx.Client = client.New(json404.URL+"/api/auth", json404.URL)
	reg := &check.Registry{}
	RegisterTable(reg)
	for _, c := range reg.All() {
		if c.ID == "table.every_route_answers" {
			if res := c.Run(ctx); res.Status != "pass" {
				t.Fatalf("a JSON 404 is an answer of the route: %s %s", res.Status, res.Detail)
			}
		}
	}
}
