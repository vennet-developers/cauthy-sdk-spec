// cauthy-api-check sends the probes of openapi/probes.yaml to a running
// Cauthy and checks every answer against openapi/cauthy.yaml: status, content
// type and body schema.
//
//	CAUTHY_API_CHECK_MEMBER_PASSWORD=… cauthy-api-check --cauthy http://localhost:8080 --tenant acme \
//	  --var member_email=member@example.com --var client_id=… [--json report.json]
//
// A secret (a password, a client secret) is passed in the environment as
// CAUTHY_API_CHECK_<NAME>, which sets {<name>}; --var name=value sets the
// rest. No value is ever printed.
//
// Exit codes: 0 every probe passed; 1 a probe failed; 2 usage or configuration
// error (including probes that leave an operation of the document unsent).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/apicheck"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/oas"
)

const envPrefix = "CAUTHY_API_CHECK_"

// varsFlag is --var name=value, repeated. It prints no value.
type varsFlag map[string]string

func (v varsFlag) String() string { return "" }

func (v varsFlag) Set(s string) error {
	name, value, ok := strings.Cut(s, "=")
	if !ok || name == "" {
		return errors.New("want name=value")
	}
	v[name] = value
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Environ(), os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args, environ []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("cauthy-api-check", flag.ContinueOnError)
	fs.SetOutput(errOut)
	cauthy := fs.String("cauthy", "", "Cauthy's address, e.g. http://localhost:8080")
	tenant := fs.String("tenant", "", "the workspace's slug, sent as X-Tenant-Key")
	docPath := fs.String("doc", "../openapi/cauthy.yaml", "the public OpenAPI document")
	probesPath := fs.String("probes", "../openapi/probes.yaml", "the probes to send")
	jsonOut := fs.String("json", "", "also write the report as JSON to this file")
	vars := varsFlag{}
	fs.Var(vars, "var", "a variable as name=value (repeatable); a secret goes in "+envPrefix+"<NAME> instead")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cauthy == "" || *tenant == "" {
		fmt.Fprintln(errOut, "--cauthy and --tenant are required")
		return 2
	}
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		if name, ok := strings.CutPrefix(k, envPrefix); ok && name != "" {
			vars[strings.ToLower(name)] = v
		}
	}
	rawDoc, err := os.ReadFile(*docPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	doc, err := oas.Load(rawDoc)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	rawProbes, err := os.ReadFile(*probesPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	file, err := apicheck.Parse(rawProbes)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	uncovered, unknown := apicheck.Coverage(doc, file)
	for _, op := range uncovered {
		fmt.Fprintf(errOut, "no probe sends %s\n", op)
	}
	for _, p := range unknown {
		fmt.Fprintf(errOut, "probe %s names an operation the document does not have\n", p)
	}
	inputs := make([]string, 0, len(vars))
	for name := range vars {
		inputs = append(inputs, name)
	}
	sort.Strings(inputs)
	unset := apicheck.Unset(file, inputs)
	for _, u := range unset {
		fmt.Fprintln(errOut, u)
	}
	if len(uncovered)+len(unknown)+len(unset) > 0 {
		return 2
	}
	rep := apicheck.Run(ctx, apicheck.Options{Base: *cauthy, Tenant: *tenant, Doc: doc, File: file, Vars: vars})
	fmt.Fprint(out, rep.Text())
	if *jsonOut != "" {
		if err := os.WriteFile(*jsonOut, rep.JSON(), 0o644); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	if !rep.Passed {
		return 1
	}
	return 0
}
