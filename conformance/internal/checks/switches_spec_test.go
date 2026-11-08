package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/oas"
)

// Every setting a switch check changes is one Cauthy's public API takes.
func TestSwitchSettingsAreInThePublicAPI(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "cauthy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := oas.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	for op, schema := range map[string]string{"PUT /v1/settings/auth": "UpdateAuthSettingsRequest", "PATCH /v1/oauth/clients/{client_id}": "OAuthClientUpdateRequest"} {
		if doc.Ops[op] == nil {
			t.Errorf("the public API lacks %s", op)
		}
		if doc.Schemas[schema] == nil {
			t.Fatalf("the public API lacks the schema %s", schema)
		}
	}
	for _, k := range SwitchSettings {
		if doc.Schemas["UpdateAuthSettingsRequest"].Properties[k] == nil {
			t.Errorf("UpdateAuthSettingsRequest has no %s", k)
		}
	}
	if doc.Schemas["OAuthClientUpdateRequest"].Properties["allow_persistent_sessions"] == nil {
		t.Error("OAuthClientUpdateRequest has no allow_persistent_sessions")
	}
	for _, op := range []string{"GET /v1/settings/auth", "GET /v1/oauth/clients", "GET /v1/users", "DELETE /v1/users/{id}"} {
		if doc.Ops[op] == nil {
			t.Errorf("the public API lacks %s, which the switch checks call", op)
		}
	}
}
