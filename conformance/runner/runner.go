// Package runner runs the auth-bff conformance suite from another program:
// the cauthy CLI wraps it as `cauthy conformance`. It is the only public door
// to the checks; everything it drives stays internal.
package runner

import (
	"errors"
	"fmt"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/checks"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

// Options says what to drive. Password is never logged or reported.
type Options struct {
	Target   string // the backend's prefix, e.g. http://localhost:3999/api/auth
	Origin   string // the application's origin, e.g. http://localhost:3999
	Email    string // a password account in the backend's tenant; "" skips the signed-in checks
	Password string
	Level    string // "basic" (default) or "strict"
	JWKSPath string // contract mode: the JWKS path the backend serves; "" otherwise
	Table    []byte // a route table instead of the embedded one; nil for the embedded
}

// Outcome is a finished run.
type Outcome struct {
	Text     string // one line per check, then the counts
	JSON     []byte // the same report as JSON, with passed, complete and counts
	Passed   bool   // no check at or below the level failed
	Complete bool   // no check at or below the level was skipped
}

// ExitCode is the runner's: 0 passed and complete, 1 a check failed, 3 nothing
// failed but a required check was skipped. (2, a usage error, is answered by
// Run as an error instead.)
func (o Outcome) ExitCode() int {
	switch {
	case !o.Passed:
		return 1
	case !o.Complete:
		return 3
	}
	return 0
}

// ErrUsage wraps every error Run answers before driving anything.
var ErrUsage = errors.New("conformance usage")

// Run drives the backend and grades it.
func Run(o Options) (Outcome, error) {
	if o.Target == "" || o.Origin == "" {
		return Outcome{}, fmt.Errorf("%w: target and origin are required", ErrUsage)
	}
	level := check.Basic
	switch o.Level {
	case "", "basic":
	case "strict":
		level = check.Strict
	default:
		return Outcome{}, fmt.Errorf("%w: unknown level %q (basic or strict)", ErrUsage, o.Level)
	}
	var table *routes.Table
	var err error
	if o.Table != nil {
		table, err = routes.Parse(o.Table)
	} else {
		table, err = routes.Embedded()
	}
	if err != nil {
		return Outcome{}, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	ctx := &check.Ctx{Client: client.New(o.Target, o.Origin), Table: table, Email: o.Email, Password: o.Password, JWKSPath: o.JWKSPath}
	reg := &check.Registry{}
	checks.RegisterAll(reg)
	rep := reg.Run(ctx, level)
	return Outcome{Text: rep.Text(), JSON: rep.JSON(), Passed: rep.Passed(), Complete: rep.Complete()}, nil
}
