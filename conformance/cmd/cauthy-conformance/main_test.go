package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

var table = filepath.Join("..", "..", "..", "protocol", "routes.yaml")

func TestRunAgainstTheFake(t *testing.T) {
	srv := fake.New(fake.Knobs{})
	defer srv.Close()
	var out bytes.Buffer
	code := run(options{
		target: srv.Target(), origin: srv.URL, email: srv.Email, password: srv.Password,
		level: "basic", table: table,
	}, &out)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "0 failed") {
		t.Fatalf("report:\n%s", out.String())
	}
	out.Reset()
	code = run(options{
		target: srv.Target(), origin: srv.URL, email: srv.Email, password: srv.Password,
		level: "strict", table: table,
	}, &out)
	if code != 1 {
		t.Fatalf("a basic-only backend must fail strict; exit %d:\n%s", code, out.String())
	}
}

func TestNoCredentialsIsIncomplete(t *testing.T) {
	srv := fake.New(fake.Knobs{})
	defer srv.Close()
	var out bytes.Buffer
	code := run(options{target: srv.Target(), origin: srv.URL, level: "basic", table: table}, &out)
	if code != 3 {
		t.Fatalf("passed but skipped checks must exit 3; exit %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "INCOMPLETE") {
		t.Fatalf("report:\n%s", out.String())
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	var out bytes.Buffer
	for name, o := range map[string]options{
		"no target":     {origin: "http://x", level: "basic", table: table},
		"no origin":     {target: "http://x", level: "basic", table: table},
		"unknown level": {target: "http://x", origin: "http://x", level: "loose", table: table},
		"missing table": {target: "http://x", origin: "http://x", level: "basic", table: "nope.yaml"},
	} {
		if code := run(o, &out); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}
