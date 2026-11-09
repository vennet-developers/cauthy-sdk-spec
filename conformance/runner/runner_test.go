package runner_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/runner"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/runner/runnertest"
)

func TestRunGradesAWellBehavedBackend(t *testing.T) {
	b := runnertest.NewBackend()
	defer b.Close()
	ctx := context.Background()
	out, err := runner.Run(ctx, runner.Options{Target: b.Target, Origin: b.URL, Email: b.Email, Password: b.Password, Level: runner.Basic})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() != 0 || !strings.Contains(out.Text, "0 failed") {
		t.Fatalf("exit %d:\n%s", out.ExitCode(), out.Text)
	}
	if strings.Contains(out.Text, b.Password) || strings.Contains(string(out.JSON), b.Password) {
		t.Fatal("the report carries the password")
	}
	strict, err := runner.Run(ctx, runner.Options{Target: b.Target, Origin: b.URL, Email: b.Email, Password: b.Password, Level: runner.Strict})
	if err != nil || strict.ExitCode() != 1 {
		t.Fatalf("a basic-only backend must fail strict: %v exit %d", err, strict.ExitCode())
	}
}

func TestRunWithoutAccountIsIncomplete(t *testing.T) {
	b := runnertest.NewBackend()
	defer b.Close()
	out, err := runner.Run(context.Background(), runner.Options{Target: b.Target, Origin: b.URL})
	if err != nil || out.ExitCode() != 3 {
		t.Fatalf("err %v exit %d", err, out.ExitCode())
	}
}

func TestRunStopsWhenCanceled(t *testing.T) {
	b := runnertest.NewBackend()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := runner.Run(ctx, runner.Options{Target: b.Target, Origin: b.URL, Email: b.Email, Password: b.Password})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if out.ExitCode() == 0 {
		t.Fatalf("a canceled run is not a certification:\n%s", out.Text)
	}
	if b.SignIns() != 0 {
		t.Fatalf("a canceled run drove the backend: %d sign-ins", b.SignIns())
	}
}

func TestRunUsageErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		o    runner.Options
		want string
	}{
		"no target":               {runner.Options{Origin: "http://x"}, "--target"},
		"no origin":               {runner.Options{Target: "http://x"}, "--origin"},
		"unknown level":           {runner.Options{Target: "http://x", Origin: "http://x", Level: "loose"}, "--level"},
		"bad table":               {runner.Options{Target: "http://x", Origin: "http://x", Table: []byte("version: 9\n")}, "table"},
		"switches without cauthy": {runner.Options{Target: "http://x", Origin: "http://x", Level: runner.Switches}, "--cauthy"},
		"cauthy without tenant":   {runner.Options{Target: "http://x", Origin: "http://x", Cauthy: "http://c", AdminToken: "t"}, "--tenant"},
		"cauthy without token":    {runner.Options{Target: "http://x", Origin: "http://x", Cauthy: "http://c", Tenant: "acme"}, "admin token"},
		"admin token over http":   {runner.Options{Target: "http://x", Origin: "http://x", Cauthy: "http://cauthy.example.com", Tenant: "acme", AdminToken: "t"}, "https"},
	} {
		_, err := runner.Run(context.Background(), tc.o)
		if !errors.Is(err, runner.ErrUsage) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want ErrUsage naming %s, got %v", name, tc.want, err)
		}
		// The message alone, for a program that prints its own prefix.
		var usage *runner.UsageError
		if !errors.As(err, &usage) || !strings.Contains(usage.Msg, tc.want) || strings.Contains(usage.Msg, "conformance usage") {
			t.Errorf("%s: want a *UsageError, got %#v", name, err)
		}
	}
}

func TestOptionsNeverShowThePassword(t *testing.T) {
	o := runner.Options{Target: "http://x/api/auth", Origin: "http://x", Email: "ana@example.com", Password: "s3cret-pw", Cauthy: "http://c", Tenant: "acme", AdminToken: "s3cret-admin", Key: "cauthy1.s3cret-key"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(verb, o); strings.Contains(got, "s3cret") || !strings.Contains(got, "ana@example.com") {
			t.Errorf("%s: %s", verb, got)
		}
	}
}

func TestKeyChecksRunOnlyWithAKey(t *testing.T) {
	b := runnertest.NewBackend()
	defer b.Close()
	out, err := runner.Run(context.Background(), runner.Options{Target: b.Target, Origin: b.URL, Email: b.Email, Password: b.Password})
	if err != nil || strings.Contains(out.Text, "key.") {
		t.Fatalf("a run without a key has key.* checks: %v\n%s", err, out.Text)
	}
}
