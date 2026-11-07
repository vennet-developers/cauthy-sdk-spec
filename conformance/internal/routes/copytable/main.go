// copytable copies protocol/routes.yaml beside the routes package so it can be
// embedded. It is the go:generate step of internal/routes, in Go so it runs
// the same on every platform (no cp on Windows).
//
//	go run ./copytable <source> <destination>
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: copytable <source> <destination>")
		os.Exit(2)
	}
	if err := copyTable(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// copyTable writes src's bytes to dst, unchanged.
func copyTable(src, dst string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, raw, 0o644)
}
