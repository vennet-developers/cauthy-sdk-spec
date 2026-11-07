package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

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
  - { id: other.text, method: GET, path: "/p/{provider}", group: other, level: basic, needs: [], success: { redirect: true }, text: true }
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
		"                  session: {type: object}",
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
	if ops != 75 {
		t.Fatalf("want 75 operationIds, got %d", ops)
	}
}
