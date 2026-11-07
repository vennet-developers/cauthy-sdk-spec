package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

func TestGeneratesPathsAndSchemas(t *testing.T) {
	table, err := routes.Parse([]byte(`version: 1
prefix: /api/auth
routes:
  - { id: sign-in.email, method: POST, path: /sign-in/email, group: sign-in, level: basic, needs: [tenant, crosssite, json],
      body: { email: {type: email, required: true}, remember: {type: boolean} },
      success: { status: 200, fields: { status: string, session: "object?" } }, errors: [invalid_email] }
  - { id: hosted.login, method: GET, path: /login, group: hosted, level: basic, needs: [], query: { return_to: {type: string} }, success: { redirect: true }, failures: redirect }
  - { id: other.events, method: GET, path: /events, group: other, level: basic, needs: [], success: { status: 200 }, stream: true }
  - { id: other.text, method: GET, path: "/p/{provider}", group: other, level: basic, needs: [tenant], query: { x: {type: string} }, success: { redirect: true }, failures: redirect }
`))
	if err != nil {
		t.Fatal(err)
	}
	out := string(Generate(table))
	for _, want := range []string{
		"openapi: 3.1.0",
		"/sign-in/email:",
		"    post:",
		"      operationId: sign-in.email",
		"              required: [email]",
		"                email: {type: string, format: email}",
		"                required: [status]",
		"                  session: {type: [object, \"null\"]}",
		"                  status: {type: string}",
		"                $ref: '#/components/schemas/Error'",
		"/login:",
		"    get:",
		"        '302':",
		"        - {name: return_to, in: query, schema: {type: string}}",
		"      x-cauthy-needs: [tenant, crosssite, json]",
		"      x-cauthy-failures: redirect",
		"text/event-stream",
		"'/p/{provider}':",
		"text/plain",
		"        '500':\n          description: not_configured",
		"        '404':\n          description: Unknown provider",
		"        - {name: provider, in: path, required: true, schema: {type: string}}",
		"servers:\n  - url: /api/auth",
		"  license: {name: MIT, identifier: MIT}",
		"          headers: {Location: {schema: {type: string}}}",
		"errors are delivered by redirect with ?auth_error=<code>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v\n%s", err, out)
	}
}

func TestGeneratedFileMatchesTheTable(t *testing.T) {
	table, err := routes.Load(filepath.Join("..", "..", "..", "protocol", "routes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "auth-bff.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(Generate(table)) {
		t.Fatal("openapi/auth-bff.yaml is stale: run go run ./cmd/gen-openapi ../protocol/routes.yaml ../openapi/auth-bff.yaml")
	}
	var doc struct {
		OpenAPI string `yaml:"openapi"`
		Paths   map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Fatalf("openapi = %q", doc.OpenAPI)
	}
	paths := map[string]bool{}
	for _, r := range table.Routes {
		paths[r.Path] = true
	}
	if len(doc.Paths) != len(paths) {
		t.Fatalf("want %d paths, got %d", len(paths), len(doc.Paths))
	}
	ops := 0
	for _, methods := range doc.Paths {
		for _, op := range methods {
			if op.OperationID == "" {
				t.Fatal("operation without operationId")
			}
			ops++
		}
	}
	if ops != len(table.Routes) {
		t.Fatalf("want %d operationIds, got %d", len(table.Routes), ops)
	}
}

func TestNullableTypes(t *testing.T) {
	for typ, want := range map[string]string{
		"string?": `{type: [string, "null"]}`,
		"email?":  `{type: [string, "null"], format: email}`,
		"uuid?":   `{type: [string, "null"], format: uuid}`,
		"email":   `{type: string, format: email}`,
	} {
		if got := schemaOf(typ); got != want {
			t.Errorf("schemaOf(%s) = %s, want %s", typ, got, want)
		}
	}
}

func responsesOf(t *testing.T, src string) map[string]any {
	t.Helper()
	table, err := routes.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			Responses map[string]any `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(Generate(table), &doc); err != nil {
		t.Fatal(err)
	}
	for _, methods := range doc.Paths {
		for _, op := range methods {
			return op.Responses
		}
	}
	t.Fatal("no operation")
	return nil
}

func TestRedirectFailuresHaveNoJSONDefault(t *testing.T) {
	plain := responsesOf(t, `version: 1
prefix: /api/auth
routes:
  - { id: a.b, method: GET, path: /x, group: other, level: basic, success: { redirect: true }, failures: redirect }
`)
	if _, ok := plain["500"]; ok {
		t.Error("no tenant: no 500 response")
	}
	if _, ok := plain["404"]; ok {
		t.Error("no path parameter: no 404 response")
	}
	if _, ok := plain["default"].(map[string]any)["content"]; ok {
		t.Error("redirect failures: default has no content")
	}

	full := responsesOf(t, `version: 1
prefix: /api/auth
routes:
  - { id: a.b, method: GET, path: "/p/{provider}", group: other, level: basic, needs: [tenant], success: { redirect: true }, failures: redirect }
`)
	if _, ok := full["default"].(map[string]any)["content"]; ok {
		t.Error("redirect failures: default has no content")
	}
	e500, _ := full["500"].(map[string]any)
	if e500 == nil || e500["description"] != "not_configured" {
		t.Fatalf("500: %v", full["500"])
	}
	if !strings.Contains(fmt.Sprint(e500["content"]), "#/components/schemas/Error") {
		t.Errorf("500 must reference the Error schema: %v", e500)
	}
	e404, _ := full["404"].(map[string]any)
	if e404 == nil || e404["description"] != "Unknown provider" || !strings.Contains(fmt.Sprint(e404["content"]), "text/plain") {
		t.Errorf("404: %v", full["404"])
	}
}
