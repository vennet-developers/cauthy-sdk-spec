// cauthy-conformance drives a backend that serves the auth-bff protocol and
// says what passes.
//
//	CONFORMANCE_PASSWORD=… cauthy-conformance --target http://localhost:3999/api/auth \
//	  --origin http://localhost:3999 --email member@example.com --level basic [--json report.json]
//
// Exit codes: 0 passed and complete; 1 a check failed; 2 usage or config
// error; 3 nothing failed but a check at or below the level was skipped.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/runner"
)

type options struct {
	target, origin, email, password, level, table, jsonOut, jwksPath string
}

func main() {
	var o options
	flag.StringVar(&o.target, "target", "", "the backend's prefix, e.g. http://localhost:3999/api/auth")
	flag.StringVar(&o.origin, "origin", "", "the application's origin, e.g. http://localhost:3999")
	flag.StringVar(&o.email, "email", "", "a password account in the backend's tenant")
	flag.StringVar(&o.level, "level", "basic", "basic or strict")
	flag.StringVar(&o.table, "table", "", "a route table to use instead of the embedded one")
	flag.StringVar(&o.jsonOut, "json", "", "also write the report as JSON to this file")
	flag.StringVar(&o.jwksPath, "jwks-path", "", "contract mode: the JWKS path the backend serves")
	flag.Usage = usage
	flag.Parse()
	// The password is read from the environment only: a flag would end up in
	// shell history and the process list.
	o.password = os.Getenv("CONFORMANCE_PASSWORD")
	os.Exit(run(o, os.Stdout, os.Stderr))
}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprintln(w, "usage: cauthy-conformance --target URL --origin URL [--email ADDRESS] [--level basic|strict] [flags]")
	flag.PrintDefaults()
	fmt.Fprint(w, `
environment:
  CONFORMANCE_PASSWORD  the test account's password (never a flag)

exit codes:
  0  every check of the level passed and none was skipped
  1  a check failed
  2  usage or configuration error
  3  nothing failed, but a check at or below the level was skipped
`)
}

// run writes the report to out and usage or configuration errors to errOut.
func run(o options, out, errOut io.Writer) int {
	var table []byte
	if o.table != "" {
		raw, err := os.ReadFile(o.table)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
		table = raw
	}
	res, err := runner.Run(runner.Options{Target: o.target, Origin: o.origin, Email: o.email, Password: o.password,
		Level: o.level, JWKSPath: o.jwksPath, Table: table})
	if err != nil {
		fmt.Fprintln(errOut, strings.TrimPrefix(err.Error(), runner.ErrUsage.Error()+": "))
		return 2
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
