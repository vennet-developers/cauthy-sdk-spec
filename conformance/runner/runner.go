// Package runner runs the auth-bff conformance suite from another program:
// the cauthy CLI wraps it as `cauthy conformance`. It is the only public door
// to the checks; everything it drives stays internal.
package runner

import (
	"context"
	"errors"
	"fmt"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/checks"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

// The levels a run grades at.
const (
	Basic  = "basic"  // what a cauthy-auth 0.x backend meets; the default
	Strict = "strict" // protocol 1 in full
)

// Options says what to drive. Password is never logged or reported, and
// Options prints without it.
type Options struct {
	Target   string // the backend's prefix, e.g. http://localhost:3999/api/auth
	Origin   string // the application's origin, e.g. http://localhost:3999
	Email    string // a password account in the backend's tenant; "" skips the signed-in checks
	Password string
	Level    string // Basic (default) or Strict
	JWKSPath string // contract mode: the JWKS path the backend serves; "" otherwise
	Table    []byte // a route table instead of the embedded one; nil for the embedded
}

// String shows the options with the password masked, so a logged Options
// never carries it.
func (o Options) String() string {
	pw := ""
	if o.Password != "" {
		pw = "[hidden]"
	}
	table := "embedded"
	if o.Table != nil {
		table = fmt.Sprintf("%d bytes", len(o.Table))
	}
	return fmt.Sprintf("{Target:%s Origin:%s Email:%s Password:%s Level:%s JWKSPath:%s Table:%s}",
		o.Target, o.Origin, o.Email, pw, o.Level, o.JWKSPath, table)
}

// GoString keeps %#v from printing the password too.
func (o Options) GoString() string { return "runner.Options" + o.String() }

// Outcome is a finished run.
type Outcome struct {
	Text string // one line per check, then the counts
	// JSON is the same report as a JSON object: protocol (int), level,
	// target, results (an array of {id, group, level, status, detail}, status
	// being pass, fail, skip, advisory or n/a), then passed and complete (the
	// verdict) and counts (status → number).
	JSON     []byte
	Passed   bool // no check at or below the level failed
	Complete bool // no check at or below the level was skipped
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

// ErrUsage matches every error Run answers before driving anything
// (errors.Is); each is a *UsageError.
var ErrUsage = errors.New("conformance usage")

// UsageError is an error Run answers before driving anything. Msg names the
// flag or input to fix, without a prefix, for a program that prints its own.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return ErrUsage.Error() + ": " + e.Msg }

// Is makes errors.Is(err, ErrUsage) true.
func (e *UsageError) Is(target error) bool { return target == ErrUsage }

func usagef(format string, a ...any) error { return &UsageError{fmt.Sprintf(format, a...)} }

// Run drives the backend and grades it. Once ctx is done no request starts,
// the checks left are skipped, and Run answers the partial Outcome with
// ctx's error.
func Run(ctx context.Context, o Options) (Outcome, error) {
	switch {
	case o.Target == "":
		return Outcome{}, usagef("--target is required (the backend's prefix, e.g. http://localhost:3999/api/auth)")
	case o.Origin == "":
		return Outcome{}, usagef("--origin is required (the application's origin, e.g. http://localhost:3999)")
	}
	level := check.Basic
	switch o.Level {
	case "", Basic:
	case Strict:
		level = check.Strict
	default:
		return Outcome{}, usagef("--level is basic or strict, not %q", o.Level)
	}
	var table *routes.Table
	var err error
	if o.Table != nil {
		table, err = routes.Parse(o.Table)
	} else {
		table, err = routes.Embedded()
	}
	if err != nil {
		return Outcome{}, usagef("the route table: %v", err)
	}
	c := &check.Ctx{Client: client.NewContext(ctx, o.Target, o.Origin), Table: table, Email: o.Email, Password: o.Password, JWKSPath: o.JWKSPath}
	reg := &check.Registry{}
	checks.RegisterAll(reg)
	rep := reg.Run(c, level)
	out := Outcome{Text: rep.Text(), JSON: rep.JSON(), Passed: rep.Passed(), Complete: rep.Complete()}
	if err := ctx.Err(); err != nil {
		out.Complete = false
		return out, fmt.Errorf("the run stopped: %w", err)
	}
	return out, nil
}
