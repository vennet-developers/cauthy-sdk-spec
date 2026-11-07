package runner_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/runner"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/runner/runnertest"
)

func TestRunGradesAWellBehavedBackend(t *testing.T) {
	b := runnertest.NewBackend()
	defer b.Close()
	out, err := runner.Run(runner.Options{Target: b.Target, Origin: b.URL, Email: b.Email, Password: b.Password, Level: "basic"})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() != 0 || !strings.Contains(out.Text, "0 failed") {
		t.Fatalf("exit %d:\n%s", out.ExitCode(), out.Text)
	}
	if strings.Contains(out.Text, b.Password) || strings.Contains(string(out.JSON), b.Password) {
		t.Fatal("the report carries the password")
	}
	strict, err := runner.Run(runner.Options{Target: b.Target, Origin: b.URL, Email: b.Email, Password: b.Password, Level: "strict"})
	if err != nil || strict.ExitCode() != 1 {
		t.Fatalf("a basic-only backend must fail strict: %v exit %d", err, strict.ExitCode())
	}
}

func TestRunWithoutAccountIsIncomplete(t *testing.T) {
	b := runnertest.NewBackend()
	defer b.Close()
	out, err := runner.Run(runner.Options{Target: b.Target, Origin: b.URL})
	if err != nil || out.ExitCode() != 3 {
		t.Fatalf("err %v exit %d", err, out.ExitCode())
	}
}

func TestRunUsageErrors(t *testing.T) {
	for name, o := range map[string]runner.Options{
		"no target":     {Origin: "http://x"},
		"no origin":     {Target: "http://x"},
		"unknown level": {Target: "http://x", Origin: "http://x", Level: "loose"},
		"bad table":     {Target: "http://x", Origin: "http://x", Table: []byte("version: 9\n")},
	} {
		if _, err := runner.Run(o); !errors.Is(err, runner.ErrUsage) {
			t.Errorf("%s: want ErrUsage, got %v", name, err)
		}
	}
}
