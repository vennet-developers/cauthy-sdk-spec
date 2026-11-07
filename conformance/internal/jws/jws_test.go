package jws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestRS256IsDeterministicAndVerifies(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{"alg": "RS256", "kid": "k", "typ": "JWT"}
	claims := map[string]any{"sub": "x", "iat": 1}
	tok := RS256(key, header, claims)
	if tok != RS256(key, header, claims) {
		t.Fatal("two signatures of the same input differ")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("%d segments", len(parts))
	}
	if parts[0] != "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsiLCJ0eXAiOiJKV1QifQ" {
		t.Fatalf("header segment %s: keys must be sorted, no padding", parts[0])
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatal(err)
	}
}

func TestSignHMAC(t *testing.T) {
	// RFC 7515 appendix A.1 signs with this key and input.
	key, _ := base64.RawURLEncoding.DecodeString("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
	h := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
	p := "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	if got := Encode(SignHMAC(key, crypto.SHA256, h, p)); got != "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" {
		t.Fatalf("got %s", got)
	}
}
