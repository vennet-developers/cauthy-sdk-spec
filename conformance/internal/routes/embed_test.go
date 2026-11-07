package routes

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedTableIsProtocolTable(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "routes.yaml"))
	if err != nil {
		t.Skip("protocol/routes.yaml is not beside this module (module cache): nothing to compare")
	}
	if !bytes.Equal(want, embedded) {
		t.Fatal("internal/routes/routes.yaml differs from protocol/routes.yaml: run go generate ./internal/routes")
	}
	tab, err := Embedded()
	if err != nil || tab.Version != 1 || len(tab.Routes) == 0 {
		t.Fatalf("embedded table: %v %+v", err, tab)
	}
}
