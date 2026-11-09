// cauthy-conformance drives a backend that serves the auth-bff protocol and
// says what passes.
//
//	CONFORMANCE_PASSWORD=… cauthy-conformance --target http://localhost:3999/api/auth \
//	  --origin http://localhost:3999 --email member@example.com --level basic [--json report.json]
//
// With --cauthy (and an admin token in the variable --admin-token-env names)
// it also flips the tenant's dashboard switches and checks the backend
// follows; --level switches requires it.
//
// Exit codes: 0 passed and complete; 1 a check failed; 2 usage or config
// error; 3 nothing failed but a check at or below the level was skipped.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/runner"
)

type options struct {
	target, origin, email, password, level, table, jsonOut, jwksPath string
	cauthy, tenant, adminTokenEnv, adminToken, clientID              string
	keyEnv, key                                                      string
	switchWait                                                       time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.target, "target", "", "the backend's prefix, e.g. http://localhost:3999/api/auth")
	flag.StringVar(&o.origin, "origin", "", "the application's origin, e.g. http://localhost:3999")
	flag.StringVar(&o.email, "email", "", "a password account in the backend's tenant")
	flag.StringVar(&o.level, "level", "basic", "basic, strict or switches")
	flag.StringVar(&o.table, "table", "", "a route table to use instead of the embedded one")
	flag.StringVar(&o.jsonOut, "json", "", "also write the report as JSON to this file")
	flag.StringVar(&o.jwksPath, "jwks-path", "", "contract mode: the JWKS path the backend serves")
	flag.StringVar(&o.cauthy, "cauthy", "", "Cauthy's address, for the dashboard-switch checks")
	flag.StringVar(&o.tenant, "tenant", "", "the backend's workspace slug in Cauthy")
	flag.StringVar(&o.adminTokenEnv, "admin-token-env", "CAUTHY_ADMIN_TOKEN", "the environment variable that holds Cauthy's admin token")
	flag.StringVar(&o.clientID, "client-id", "", "the backend's OAuth client in Cauthy, for the persistent-sessions switch")
	flag.StringVar(&o.keyEnv, "key-env", "", "the environment variable holding the CAUTHY_KEY the backend runs on; adds the key.* checks")
	flag.DurationVar(&o.switchWait, "switch-wait", 10*time.Second, "how long the backend has to follow a switch")
	flag.Usage = usage
	flag.Parse()
	// The password, the admin token and the key are read from the environment only: a
	// flag would end up in shell history and the process list.
	o.password = os.Getenv("CONFORMANCE_PASSWORD")
	if o.cauthy != "" {
		o.adminToken = os.Getenv(o.adminTokenEnv)
	}
	if o.keyEnv != "" {
		o.key = os.Getenv(o.keyEnv)
	}
	// Ctrl-C stops the run: no request starts after it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, o, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprintln(w, "usage: cauthy-conformance --target URL --origin URL [--email ADDRESS] [--level basic|strict] [flags]")
	flag.PrintDefaults()
	fmt.Fprint(w, `
environment:
  CONFORMANCE_PASSWORD  the test account's password (never a flag)
  CAUTHY_ADMIN_TOKEN    with --cauthy: a token of the tenant's admin (another name with --admin-token-env)
  (--key-env NAME)      the CAUTHY_KEY the backend runs on, for the key.* checks; never printed

exit codes:
  0  every check of the level passed and none was skipped
  1  a check failed
  2  usage or configuration error
  3  nothing failed, but a check at or below the level was skipped
`)
}

// run writes the report to out and usage or configuration errors to errOut.
func run(ctx context.Context, o options, out, errOut io.Writer) int {
	if o.keyEnv != "" && o.key == "" {
		fmt.Fprintf(errOut, "--key-env %s: the variable is empty\n", o.keyEnv)
		return 2
	}
	var table []byte
	if o.table != "" {
		raw, err := os.ReadFile(o.table)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
		table = raw
	}
	res, err := runner.Run(ctx, runner.Options{Target: o.target, Origin: o.origin, Email: o.email, Password: o.password,
		Level: o.level, JWKSPath: o.jwksPath, Table: table,
		Cauthy: o.cauthy, Tenant: o.tenant, AdminToken: o.adminToken, ClientID: o.clientID, SwitchWait: o.switchWait, Key: o.key})
	var usage *runner.UsageError
	if errors.As(err, &usage) {
		fmt.Fprintln(errOut, usage.Msg)
		return 2
	}
	if err != nil {
		fmt.Fprint(out, res.Text)
		fmt.Fprintln(errOut, err)
		return 1
	}
	fmt.Fprint(out, res.Text)
	if o.jsonOut != "" {
		if err := os.WriteFile(o.jsonOut, res.JSON, 0o644); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	return res.ExitCode()
}
