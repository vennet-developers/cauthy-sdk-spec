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
	"path/filepath"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/checks"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
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
	flag.StringVar(&o.table, "table", defaultTable(), "path to protocol/routes.yaml")
	flag.StringVar(&o.jsonOut, "json", "", "also write the report as JSON to this file")
	flag.StringVar(&o.jwksPath, "jwks-path", "", "contract mode: the JWKS path the backend serves")
	flag.Parse()
	// The password is read from the environment only: a flag would end up in
	// shell history and the process list.
	o.password = os.Getenv("CONFORMANCE_PASSWORD")
	os.Exit(run(o, os.Stdout))
}

// defaultTable finds protocol/routes.yaml next to a checkout, or in the binary's directory.
func defaultTable() string {
	for _, p := range []string{filepath.Join("..", "protocol", "routes.yaml"), filepath.Join("protocol", "routes.yaml")} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "routes.yaml")
}

func run(o options, out io.Writer) int {
	if o.target == "" || o.origin == "" {
		fmt.Fprintln(out, "--target and --origin are required")
		return 2
	}
	level := check.Basic
	switch o.level {
	case "basic":
	case "strict":
		level = check.Strict
	default:
		fmt.Fprintf(out, "unknown level %q (basic or strict)\n", o.level)
		return 2
	}
	table, err := routes.Load(o.table)
	if err != nil {
		fmt.Fprintln(out, err)
		return 2
	}
	ctx := &check.Ctx{Client: client.New(o.target, o.origin), Table: table, Email: o.email, Password: o.password, JWKSPath: o.jwksPath}
	reg := &check.Registry{}
	checks.RegisterAll(reg)
	rep := reg.Run(ctx, level)
	fmt.Fprint(out, rep.Text())
	if o.jsonOut != "" {
		if err := os.WriteFile(o.jsonOut, rep.JSON(), 0o644); err != nil {
			fmt.Fprintln(out, err)
			return 2
		}
	}
	switch {
	case !rep.Passed():
		return 1
	case !rep.Complete():
		return 3 // nothing failed, but some required checks were skipped: not a certification
	}
	return 0
}
