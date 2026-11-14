// gen-key-vectors writes vectors/cauthy-key.json from key/cauthy-key.md's
// reference implementation. Deterministic: Ed25519 signatures are, and every
// input is fixed. Usage: go run ./cmd/gen-key-vectors ../vectors
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/cauthykey"
)

const secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" // bytes 00..1f: a test value
const client = "client_0123456789abcdef0123456789abcdef"

type valid struct {
	Name      string            `json:"name"`
	Key       string            `json:"key"`
	Issuer    string            `json:"issuer"`
	ClientID  string            `json:"client_id"`
	Secret    string            `json:"secret"`
	Derived   map[string]string `json:"derived"`
	PublicJWK map[string]string `json:"public_jwk"`
	KID       string            `json:"kid"`
	Assertion assertion         `json:"assertion"`
}

type assertion struct {
	TokenEndpoint string `json:"token_endpoint"`
	Jti           string `json:"jti"`
	Iat           int64  `json:"iat"`
	JWS           string `json:"jws"`
}

type invalid struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

func must(s string, err error) string {
	if err != nil {
		panic(err)
	}
	return s
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen-key-vectors <vectors dir>")
		os.Exit(2)
	}
	now := time.Unix(1793836800, 0)
	var vs []valid
	for _, c := range []struct{ name, issuer, client, wrap string }{
		{"valid/basic", "https://cauthy.api.example.com", client, "%s"},
		{"valid/local", "http://localhost:8080", client, "%s"},
		{"valid/loopback-port", "http://127.0.0.1:3001", client, "%s"},
		{"valid/surrounding-whitespace", "https://cauthy.api.example.com", client, " \t%s\r\n"},
	} {
		key := must(cauthykey.Compose(c.issuer, c.client, secret))
		k, err := cauthykey.Parse(key)
		if err != nil {
			panic(err)
		}
		d := k.Derive()
		der := map[string]string{}
		for l, b := range d.Labels {
			der[l] = hex.EncodeToString(b)
		}
		te := c.issuer + "/v1/oauth/token"
		jti := "00000000-0000-4000-8000-000000000000"
		vs = append(vs, valid{Name: c.name, Key: fmt.Sprintf(c.wrap, key), Issuer: c.issuer, ClientID: c.client, Secret: secret,
			Derived: der, PublicJWK: d.PublicJWK(), KID: d.KID,
			Assertion: assertion{TokenEndpoint: te, Jti: jti, Iat: now.Unix(), JWS: d.Assertion(c.client, te, jti, now)}})
	}
	basic := vs[0].Key
	flip := []byte(basic)
	flip[len(flip)-1] ^= 1
	if flip[len(flip)-1] == basic[len(basic)-1] {
		panic("flip")
	}
	u := cauthykey.ComposeUnchecked
	is := []invalid{
		{"invalid/empty", "", cauthykey.ReasonFormat},
		{"invalid/three-parts", "cauthy1.YQ.Yg", cauthykey.ReasonFormat},
		{"invalid/client-secret", "cs_0123456789abcdef", cauthykey.ReasonFormat},
		{"invalid/newer-version", "cauthy2.YQ.Yg.Yw.ZA", cauthykey.ReasonVersion},
		{"invalid/too-long", "cauthy1." + strings.Repeat("A", 600), cauthykey.ReasonFormat},
		{"invalid/inner-space", strings.Replace(basic, ".", ". ", 1), cauthykey.ReasonFormat},
		{"invalid/checksum", string(flip), cauthykey.ReasonChecksum},
		{"invalid/truncated", basic[:len(basic)-12] + basic[len(basic)-9:], cauthykey.ReasonChecksum},
		{"invalid/issuer-http-remote", u("http://cauthy.api.example.com", client, secret), cauthykey.ReasonIssuer},
		{"invalid/issuer-trailing-slash", u("https://cauthy.api.example.com/", client, secret), cauthykey.ReasonIssuer},
		{"invalid/issuer-path", u("https://cauthy.api.example.com/v1", client, secret), cauthykey.ReasonIssuer},
		{"invalid/issuer-uppercase", u("https://Cauthy.api.example.com", client, secret), cauthykey.ReasonIssuer},
		{"invalid/issuer-userinfo", u("https://a@cauthy.api.example.com", client, secret), cauthykey.ReasonIssuer},
		{"invalid/issuer-default-port", u("https://cauthy.api.example.com:443", client, secret), cauthykey.ReasonIssuer},
		{"invalid/issuer-not-ascii", u("https://cauthý.example.com", client, secret), cauthykey.ReasonIssuer},
		{"invalid/issuer-empty-port", u("https://cauthy.api.example.com:", client, secret), cauthykey.ReasonIssuer},
		{"invalid/issuer-port-leading-zero", u("https://cauthy.api.example.com:08443", client, secret), cauthykey.ReasonIssuer},
		{"invalid/issuer-ipv4-shorthand", u("https://127.1", client, secret), cauthykey.ReasonIssuer},
		{"invalid/client-space", u("https://cauthy.api.example.com", "client 1", secret), cauthykey.ReasonClient},
		{"invalid/client-too-long", u("https://cauthy.api.example.com", strings.Repeat("c", 129), secret), cauthykey.ReasonClient},
		{"invalid/secret-short", u("https://cauthy.api.example.com", client, secret[:42]), cauthykey.ReasonSecret},
		{"invalid/secret-not-canonical", u("https://cauthy.api.example.com", client, secret[:42]+"h"), cauthykey.ReasonSecret},
	}
	for _, c := range is {
		_, err := cauthykey.Parse(c.Key)
		e, ok := err.(*cauthykey.Error)
		if !ok || e.Reason != c.Reason {
			panic(fmt.Sprintf("%s: got %v, want %s", c.Name, err, c.Reason))
		}
	}
	out := map[string]any{
		"comment": "GENERATED by conformance/cmd/gen-key-vectors from key/cauthy-key.md. Do not edit. Every secret here is a test value.",
		"version": 1, "valid": vs, "invalid": is,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(os.Args[1], "cauthy-key.json"), append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}
