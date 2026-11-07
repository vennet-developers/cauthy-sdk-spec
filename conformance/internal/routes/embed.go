package routes

import (
	_ "embed"
	"sync"
)

// The route table, embedded so the runner works from the module cache, where
// protocol/ (outside this module) is not present. CI keeps it equal to
// protocol/routes.yaml.
//
//go:generate go run ./copytable ../../../protocol/routes.yaml routes.yaml
//go:embed routes.yaml
var embedded []byte

var (
	embeddedOnce  sync.Once
	embeddedTable *Table
	embeddedErr   error
)

// Embedded is the route table this module was built with.
func Embedded() (*Table, error) {
	embeddedOnce.Do(func() { embeddedTable, embeddedErr = Parse(embedded) })
	return embeddedTable, embeddedErr
}
