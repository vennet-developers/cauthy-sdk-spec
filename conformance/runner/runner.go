// Package runner runs the auth-bff conformance suite from another program:
// the cauthy CLI wraps it as `cauthy conformance`. It is the only public door
// to the checks; everything it drives stays internal.
package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/admin"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/checks"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

// The levels a run grades at.
const (
	Basic    = "basic"    // what a cauthy-auth 0.x backend meets; the default
	Strict   = "strict"   // protocol 1 in full
	Switches = "switches" // strict, plus the dashboard switches (needs Cauthy)
)

// Options says what to drive. Password is never logged or reported, and
// Options prints without it.
type Options struct {
	Target   string // the backend's prefix, e.g. http://localhost:3999/api/auth
	Origin   string // the application's origin, e.g. http://localhost:3999
	Email    string // a password account in the backend's tenant; "" skips the signed-in checks
	Password string
	Level    string // Basic (default), Strict or Switches
	JWKSPath string // contract mode: the JWKS path the backend serves; "" otherwise
	Table    []byte // a route table instead of the embedded one; nil for the embedded

	// The dashboard-switch checks change the tenant's settings in Cauthy and
	// put them back. Without Cauthy they skip (and level switches is refused).
	Cauthy     string        // Cauthy's address, e.g. http://localhost:8080
	Tenant     string        // the backend's workspace slug
	AdminToken string        // a token with settings:manage, oauth_clients:manage, users:manage and users:delete; never printed
	ClientID   string        // the backend's OAuth client, for the persistent-sessions switch; "" skips that one
	SwitchWait time.Duration // how long the backend has to follow a switch; 0 is 10 s
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
	token := ""
	if o.AdminToken != "" {
		token = "[hidden]"
	}
	return fmt.Sprintf("{Target:%s Origin:%s Email:%s Password:%s Level:%s JWKSPath:%s Table:%s Cauthy:%s Tenant:%s AdminToken:%s ClientID:%s SwitchWait:%s}",
		o.Target, o.Origin, o.Email, pw, o.Level, o.JWKSPath, table, o.Cauthy, o.Tenant, token, o.ClientID, o.SwitchWait)
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
	case Switches:
		level = check.Switches
		if o.Cauthy == "" {
			return Outcome{}, usagef("--level switches needs --cauthy (Cauthy's address) and an admin token")
		}
	default:
		return Outcome{}, usagef("--level is basic, strict or switches, not %q", o.Level)
	}
	if o.Cauthy != "" && o.Tenant == "" {
		return Outcome{}, usagef("--cauthy needs --tenant (the backend's workspace slug)")
	}
	if o.Cauthy != "" && o.AdminToken == "" {
		return Outcome{}, usagef("--cauthy needs an admin token (--admin-token-env names the variable that holds it)")
	}
	if o.Cauthy != "" && !safeForToken(o.Cauthy) {
		return Outcome{}, usagef("--cauthy carries an admin token: it must be https, or http on this machine (localhost)")
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
	c := &check.Ctx{Client: client.NewContext(ctx, o.Target, o.Origin), Table: table, Email: o.Email, Password: o.Password, JWKSPath: o.JWKSPath,
		SwitchWait: o.SwitchWait}
	if o.Cauthy != "" {
		c.Admin = admin.New(ctx, o.Cauthy, o.Tenant, o.AdminToken, o.ClientID)
	}
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

// safeForToken is true for an https address, or an http one on this machine.
func safeForToken(addr string) bool {
	u, err := url.Parse(addr)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		if h == "localhost" || strings.HasSuffix(h, ".localhost") {
			return true
		}
		ip := net.ParseIP(h)
		return ip != nil && ip.IsLoopback()
	}
	return false
}
