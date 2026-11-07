// gen-openapi writes openapi/auth-bff.yaml from protocol/routes.yaml.
//
//	go run ./cmd/gen-openapi ../protocol/routes.yaml ../openapi/auth-bff.yaml
package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gen-openapi <routes.yaml> <out.yaml>")
		os.Exit(2)
	}
	table, err := routes.Load(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[2], Generate(table), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// schemaOf renders a table type. T? may be absent or null, so it is nullable.
func schemaOf(typ string) string {
	base := strings.TrimSuffix(typ, "?")
	nullable := base != typ
	var format string
	switch base {
	case "email", "uuid":
		format = ", format: " + base
		base = "string"
	case "string", "number", "boolean", "object", "array":
	default:
		return "{}"
	}
	if nullable {
		return `{type: [` + base + `, "null"]` + format + "}"
	}
	return "{type: " + base + format + "}"
}

// pathParamsOf lists the {name} segments of a path in order.
func pathParamsOf(path string) []string {
	var names []string
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			names = append(names, seg[1:len(seg)-1])
		}
	}
	return names
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Generate renders the table as OpenAPI 3.1. The output is deterministic:
// paths in table order, fields sorted by name.
func Generate(t *routes.Table) []byte {
	var b bytes.Buffer
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("# GENERATED from protocol/routes.yaml by conformance/cmd/gen-openapi. Do not edit.")
	w("openapi: 3.1.0")
	w("info:")
	w("  title: Cauthy auth-bff protocol")
	w("  version: '%d'", t.Version)
	w("  description: The /api/auth/* routes a backend SDK serves and a client SDK consumes. Relative to the prefix %s.", t.Prefix)
	w("  license: {name: MIT, identifier: MIT}")
	w("servers:")
	w("  - url: %s", t.Prefix)
	w("paths:")
	byPath := map[string][]*routes.Route{}
	var order []string
	for _, r := range t.Routes {
		if byPath[r.Path] == nil {
			order = append(order, r.Path)
		}
		byPath[r.Path] = append(byPath[r.Path], r)
	}
	for _, path := range order {
		key := path
		if strings.ContainsAny(path, "{}") {
			key = "'" + path + "'"
		}
		w("  %s:", key)
		for _, r := range byPath[path] {
			w("    %s:", strings.ToLower(r.Method))
			w("      operationId: %s", r.ID)
			w("      tags: [%s]", r.Group)
			if r.Deprecated {
				w("      deprecated: true")
			}
			w("      x-cauthy-level: %s", r.Level)
			w("      x-cauthy-needs: [%s]", strings.Join(r.NeedsList, ", "))
			if r.Failures != "" {
				w("      x-cauthy-failures: %s", r.Failures)
			}
			if len(r.Sets) > 0 {
				w("      x-cauthy-sets-cookies: [%s]", strings.Join(r.Sets, ", "))
			}
			if len(r.Clears) > 0 {
				w("      x-cauthy-clears-cookies: [%s]", strings.Join(r.Clears, ", "))
			}
			pathParams := pathParamsOf(r.Path)
			if len(pathParams) > 0 || len(r.Query) > 0 {
				w("      parameters:")
				for _, name := range pathParams {
					w("        - {name: %s, in: path, required: true, schema: {type: string}}", name)
				}
				for _, k := range sortedKeys(r.Query) {
					f := r.Query[k]
					req := ""
					if f.Required {
						req = ", required: true"
					}
					w("        - {name: %s, in: query, schema: %s%s}", k, schemaOf(f.Type), req)
				}
			}
			if r.Needs("json") {
				w("      requestBody:")
				w("        required: true")
				w("        content:")
				w("          application/json:")
				w("            schema:")
				w("              type: object")
				var required []string
				for _, k := range sortedKeys(r.Body) {
					if r.Body[k].Required {
						required = append(required, k)
					}
				}
				if len(required) > 0 {
					w("              required: [%s]", strings.Join(required, ", "))
				}
				if len(r.Body) > 0 {
					w("              properties:")
					for _, k := range sortedKeys(r.Body) {
						w("                %s: %s", k, schemaOf(r.Body[k].Type))
					}
				}
			}
			w("      responses:")
			switch {
			case r.Success.Redirect:
				w("        '302':")
				w("          description: Redirect")
				w("          headers: {Location: {schema: {type: string}}}")
			case r.Stream:
				w("        '%d':", r.Success.Status)
				w("          description: Server-sent events")
				w("          content:")
				w("            text/event-stream:")
				w("              schema: {type: string}")
			default:
				w("        '%d':", r.Success.Status)
				w("          description: Success")
				if len(r.Success.Fields) > 0 {
					w("          content:")
					w("            application/json:")
					w("              schema:")
					w("                type: object")
					var required []string
					for _, k := range sortedKeys(r.Success.Fields) {
						if !strings.HasSuffix(r.Success.Fields[k], "?") {
							required = append(required, k)
						}
					}
					if len(required) > 0 {
						w("                required: [%s]", strings.Join(required, ", "))
					}
					w("                properties:")
					for _, k := range sortedKeys(r.Success.Fields) {
						w("                  %s: %s", k, schemaOf(r.Success.Fields[k]))
					}
				}
			}
			w("        default:")
			if r.Failures == "redirect" {
				w("          description: Failures are not errors in JSON; errors are delivered by redirect with ?auth_error=<code> (%s)", strings.Join(append([]string{"bad_request"}, r.Errors...), ", "))
				continue
			}
			w("          description: Error (%s)", strings.Join(append([]string{"bad_request"}, r.Errors...), ", "))
			if r.Text {
				w("          content:")
				w("            text/plain:")
				w("              schema: {type: string}")
			} else {
				w("          content:")
				w("            application/json:")
				w("              schema:")
				w("                $ref: '#/components/schemas/Error'")
			}
		}
	}
	w("components:")
	w("  schemas:")
	w("    Error:")
	w("      type: object")
	w("      required: [error]")
	w("      properties:")
	w("        error:")
	w("          type: object")
	w("          required: [code, message]")
	w("          properties:")
	w("            code: {type: string}")
	w("            message: {type: string}")
	w("            field: {type: string}")
	w("            reasons: {type: array, items: {type: string}}")
	return b.Bytes()
}
