package admin_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/admin"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

func setup(t *testing.T) (*fake.Server, *admin.Client) {
	t.Helper()
	srv := fake.New(fake.Knobs{})
	t.Cleanup(srv.Close)
	base := srv.StartCauthy("s3cret-admin")
	return srv, admin.New(context.Background(), base, fake.Tenant, "s3cret-admin", fake.ClientID)
}

func TestSetChangesAndRestorePutsBack(t *testing.T) {
	srv, a := setup(t)
	if err := a.Set(map[string]any{"allow_signup": false, "allow_magic_link": true}); err != nil {
		t.Fatal(err)
	}
	if err := a.Set(map[string]any{"allow_signup": true}); err != nil {
		t.Fatal(err)
	}
	if srv.Setting("allow_signup") != true || srv.Setting("allow_magic_link") != true {
		t.Fatalf("not set: %v %v", srv.Setting("allow_signup"), srv.Setting("allow_magic_link"))
	}
	if errs := a.Restore(); len(errs) != 0 {
		t.Fatal(errs)
	}
	// As first found, not as last set.
	if srv.Setting("allow_signup") != true || srv.Setting("allow_magic_link") != false {
		t.Fatalf("not restored: %v %v", srv.Setting("allow_signup"), srv.Setting("allow_magic_link"))
	}
}

func TestSetPersistentAndRestore(t *testing.T) {
	srv, a := setup(t)
	if err := a.SetPersistent(true); err != nil {
		t.Fatal(err)
	}
	if !srv.ClientPersistent() {
		t.Fatal("not set")
	}
	a.Restore()
	if srv.ClientPersistent() {
		t.Fatal("not restored")
	}
	a.ClientID = ""
	if err := a.SetPersistent(true); err == nil || !strings.Contains(err.Error(), "--client-id") {
		t.Fatalf("want an error naming --client-id, got %v", err)
	}
}

func TestRestoreDeletesTheAccountsMade(t *testing.T) {
	srv, a := setup(t)
	browser := client.New(srv.Target(), srv.URL)
	res, err := browser.PostJSON("/sign-up/email", map[string]any{"email": "switch-1@example.com", "password": "Sw1tch-long-enough!"}, nil)
	if err != nil || res.Status != 200 {
		t.Fatalf("%v %v", res, err)
	}
	a.Made("switch-1@example.com")
	a.Made("never-made@example.com")
	if errs := a.Restore(); len(errs) != 0 {
		t.Fatal(errs)
	}
	if got := srv.Accounts(); len(got) != 0 {
		t.Fatalf("left %v", got)
	}
}

func TestCauthysRefusalIsAnErrorWithoutTheToken(t *testing.T) {
	_, good := setup(t)
	a := admin.New(context.Background(), good.Base, fake.Tenant, "s3cret-wrong", fake.ClientID)
	err := a.Set(map[string]any{"allow_signup": false})
	if err == nil || !strings.Contains(err.Error(), "401 unauthorized") || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("%v", err)
	}
	if err := a.Set(map[string]any{"allow_password": false}); err == nil {
		t.Fatal("want an error")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(verb, a); strings.Contains(got, "s3cret") {
			t.Errorf("%s shows the token: %s", verb, got)
		}
	}
}

func TestCauthyKeepsOneWayIn(t *testing.T) {
	_, a := setup(t)
	err := a.Set(map[string]any{"allow_password": false})
	if err == nil || !strings.Contains(err.Error(), "409 last_method") {
		t.Fatalf("want 409 last_method, got %v", err)
	}
}

// Cauthy's rate limit answers 429 with Retry-After: the client waits and
// tries again, so a tenant is still put back when a run trips the limit.
func TestARateLimitedCallWaitsAndTriesAgain(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"errors":[{"code":"rate_limited"}]}`))
			return
		}
		w.Write([]byte(`{"data":{"allow_signup":true}}`))
	}))
	defer srv.Close()
	a := admin.New(context.Background(), srv.URL, "acme", "t", "")
	got, err := a.Settings()
	if err != nil || got["allow_signup"] != true || n.Load() != 2 {
		t.Fatalf("%v %v after %d calls", got, err, n.Load())
	}
}

func TestARateLimitThatStaysIsAnError(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"errors":[{"code":"rate_limited"}]}`))
	}))
	defer srv.Close()
	a := admin.New(context.Background(), srv.URL, "acme", "t", "")
	if _, err := a.Settings(); err == nil || !strings.Contains(err.Error(), "429 rate_limited") || n.Load() != 3 {
		t.Fatalf("%v after %d calls", err, n.Load())
	}
}
