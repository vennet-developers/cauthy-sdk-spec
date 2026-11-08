// gen-apitypes writes the Go types of Cauthy's public OpenAPI document.
//
//	go run ./cmd/gen-apitypes ../openapi/cauthy.yaml ../go/cauthyapi/types.gen.go
package main

import (
	"fmt"
	"os"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/apigen"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/oas"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gen-apitypes <openapi/cauthy.yaml> <go/cauthyapi/types.gen.go>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(in, out string) error {
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	doc, err := oas.Load(raw)
	if err != nil {
		return err
	}
	src, err := apigen.Generate(doc, "cauthyapi", "openapi/cauthy.yaml")
	if err != nil {
		return err
	}
	return os.WriteFile(out, src, 0o644)
}
