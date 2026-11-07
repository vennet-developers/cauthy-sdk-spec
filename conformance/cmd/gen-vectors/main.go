// gen-vectors writes vectors/jwks.json and vectors/tokens.json from the
// test-only keys in vectors/keys. This first version only makes the keys.
//
//	go run ./cmd/gen-vectors -make-keys ../vectors/keys
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

var b64 = base64.RawURLEncoding

func main() {
	makeKeys := flag.Bool("make-keys", false, "write the key files missing in <keys dir>, then stop")
	flag.Parse()
	if !*makeKeys || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gen-vectors -make-keys <keys dir>")
		os.Exit(2)
	}
	if err := MakeKeys(flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
