package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

var table = filepath.Join("..", "..", "..", "protocol", "routes.yaml")

func TestRunAgainstTheFake(t *testing.T) {
	srv := fake.New(fake.Knobs{})
	defer srv.Close()
	var out bytes.Buffer
	code := run(context.Background(), options{
		target: srv.Target(), origin: srv.URL, email: srv.Email, password: srv.Password,
		level: "basic", table: table,
	}, &out, &out)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "0 failed") {
		t.Fatalf("report:\n%s", out.String())
	}
	out.Reset()
	code = run(context.Background(), options{
		target: srv.Target(), origin: srv.URL, email: srv.Email, password: srv.Password,
		level: "strict", table: table,
	}, &out, &out)
	if code != 1 {
		t.Fatalf("a basic-only backend must fail strict; exit %d:\n%s", code, out.String())
	}
}

func TestNoCredentialsIsIncomplete(t *testing.T) {
	srv := fake.New(fake.Knobs{})
	defer srv.Close()
	var out bytes.Buffer
	code := run(context.Background(), options{target: srv.Target(), origin: srv.URL, level: "basic", table: table}, &out, &out)
	if code != 3 {
		t.Fatalf("passed but skipped checks must exit 3; exit %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "INCOMPLETE") {
		t.Fatalf("report:\n%s", out.String())
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	var out, errOut bytes.Buffer
	for name, o := range map[string]options{
		"no target":     {origin: "http://x", level: "basic", table: table},
		"no origin":     {target: "http://x", level: "basic", table: table},
		"unknown level": {target: "http://x", origin: "http://x", level: "loose", table: table},
		"missing table": {target: "http://x", origin: "http://x", level: "basic", table: "nope.yaml"},
	} {
		errOut.Reset()
		if code := run(context.Background(), o, &out, &errOut); code != 2 || errOut.Len() == 0 || out.Len() != 0 {
			t.Errorf("%s: exit %d, stderr %q, stdout %q; want 2, a message on stderr only", name, code, errOut.String(), out.String())
		}
	}
}

func TestJSONReport(t *testing.T) {
	srv := fake.New(fake.Knobs{})
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "report.json")
	var out bytes.Buffer
	code := run(context.Background(), options{target: srv.Target(), origin: srv.URL, email: srv.Email, password: srv.Password, level: "basic", table: table, jsonOut: path}, &out, &out)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Passed, Complete bool
		Counts           map[string]int
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if !d.Passed || !d.Complete || d.Counts["n/a"] != 1 {
		t.Fatalf("json: %s", raw)
	}
}

func TestJSONWriteFailureExits2(t *testing.T) {
	srv := fake.New(fake.Knobs{})
	defer srv.Close()
	var out, errOut bytes.Buffer
	bad := filepath.Join(t.TempDir(), "no-such-dir", "report.json")
	code := run(context.Background(), options{target: srv.Target(), origin: srv.URL, email: srv.Email, password: srv.Password, level: "basic", table: table, jsonOut: bad}, &out, &errOut)
	if code != 2 || errOut.Len() == 0 {
		t.Fatalf("exit %d, stderr %q; want 2 with a message", code, errOut.String())
	}
}

func TestSwitchesAgainstTheFake(t *testing.T) {
	for name, tc := range map[string]struct {
		k    fake.Knobs
		code int
	}{
		"follows the dashboard": {fake.Knobs{Strict: true}, 0},
		"reads settings once":   {fake.Knobs{Strict: true, StaleSettings: true}, 1},
	} {
		srv := fake.New(tc.k)
		base := srv.StartCauthy("admin-token")
		var out bytes.Buffer
		code := run(context.Background(), options{
			target: srv.Target(), origin: srv.URL, email: srv.Email, password: srv.Password, level: "switches", table: table,
			cauthy: base, tenant: fake.Tenant, adminToken: "admin-token", clientID: fake.ClientID, switchWait: time.Second,
		}, &out, &out)
		srv.Close()
		if code != tc.code || !strings.Contains(out.String(), "switches.sign_up") || strings.Contains(out.String(), "admin-token") {
			t.Errorf("%s: exit %d, want %d:\n%s", name, code, tc.code, out.String())
		}
	}
}

func TestSwitchesWithoutCauthyIsAUsageError(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), options{target: "http://x", origin: "http://x", level: "switches", table: table}, &out, &errOut)
	if code != 2 || !strings.Contains(errOut.String(), "--cauthy") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
}

func TestKeyEnvEmptyExits2(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), options{target: "http://x", origin: "http://x", level: "basic", table: table, keyEnv: "ACME_CAUTHY_KEY"}, &out, &errOut)
	if code != 2 || !strings.Contains(errOut.String(), "--key-env ACME_CAUTHY_KEY") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
}

func TestKeyAgainstTheFake(t *testing.T) {
	srv := fake.New(fake.Knobs{Strict: true})
	defer srv.Close()
	base := srv.StartCauthy("admin-token")
	key := srv.IssueKey(base)
	var out bytes.Buffer
	code := run(context.Background(), options{
		target: srv.Target(), origin: srv.URL, email: srv.Email, password: srv.Password, level: "strict", table: table,
		cauthy: base, tenant: fake.Tenant, adminToken: "admin-token", clientID: fake.ClientID, keyEnv: "CAUTHY_KEY", key: key,
	}, &out, &out)
	if code != 0 || !strings.Contains(out.String(), "key.identity") || strings.Contains(out.String(), key) {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
}
