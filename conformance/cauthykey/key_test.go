package cauthykey

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// The test secret: bytes 00..1f. Never a real key.
const testSecret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
const testClient = "client_0123456789abcdef0123456789abcdef"
const testKey = "cauthy1.aHR0cHM6Ly9jYXV0aHkuYXBpLmV4YW1wbGUuY29t.Y2xpZW50XzAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.AAvYhJZh"

func TestComposeAndParse(t *testing.T) {
	k, err := Compose("https://cauthy.api.example.com", testClient, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if k != testKey {
		t.Fatalf("Compose = %s", k)
	}
	got, err := Parse("  \n" + k + "\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != "https://cauthy.api.example.com" || got.ClientID != testClient || got.Secret != testSecret {
		t.Fatalf("Parse = %+v", got)
	}
}

func reasonOf(t *testing.T, s string) string {
	t.Helper()
	_, err := Parse(s)
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("Parse(%q) = %v, want *Error", s, err)
	}
	if strings.Contains(e.Error(), testSecret) {
		t.Fatalf("the error shows the secret: %s", e.Error())
	}
	return e.Reason
}

func TestParseRefusals(t *testing.T) {
	flip := []byte(testKey)
	flip[len(flip)-1] = 'i' // last checksum character changed
	unchecked := func(issuer, client, secret string) string { return composeUnchecked(issuer, client, secret) }
	for _, c := range []struct{ name, key, reason string }{
		{"empty", "", ReasonFormat},
		{"three parts", "cauthy1.a.b", ReasonFormat},
		{"newer version", "cauthy2.a.b.c.d", ReasonVersion},
		{"not a key", "cs_0123", ReasonFormat},
		{"too long", "cauthy1." + strings.Repeat("A", 600), ReasonFormat},
		{"not ascii", "cauthy1.é.b.c.d", ReasonFormat},
		{"checksum", string(flip), ReasonChecksum},
		{"http elsewhere", unchecked("http://cauthy.api.example.com", testClient, testSecret), ReasonIssuer},
		{"path", unchecked("https://cauthy.api.example.com/", testClient, testSecret), ReasonIssuer},
		{"upper host", unchecked("https://Cauthy.api.example.com", testClient, testSecret), ReasonIssuer},
		{"userinfo", unchecked("https://a@cauthy.api.example.com", testClient, testSecret), ReasonIssuer},
		{"default port", unchecked("https://cauthy.api.example.com:443", testClient, testSecret), ReasonIssuer},
		{"not ascii host", unchecked("https://cauthý.example.com", testClient, testSecret), ReasonIssuer},
		{"client space", unchecked("https://cauthy.api.example.com", "client 1", testSecret), ReasonClient},
		{"client long", unchecked("https://cauthy.api.example.com", strings.Repeat("c", 129), testSecret), ReasonClient},
		{"secret short", unchecked("https://cauthy.api.example.com", testClient, testSecret[:42]), ReasonSecret},
		{"secret not canonical", unchecked("https://cauthy.api.example.com", testClient, testSecret[:42]+"h"), ReasonSecret},
	} {
		if got := reasonOf(t, c.key); got != c.reason {
			t.Errorf("%s: reason %s, want %s", c.name, got, c.reason)
		}
	}
}

func TestLocalIssuers(t *testing.T) {
	for _, iss := range []string{"http://localhost:8080", "http://127.0.0.1:3001", "http://[::1]:8080", "https://id.test"} {
		if _, err := Compose(iss, testClient, testSecret); err != nil {
			t.Errorf("%s: %v", iss, err)
		}
	}
}

func TestDerive(t *testing.T) {
	k, _ := Parse(testKey)
	d := k.Derive()
	for label, want := range map[string]string{
		"pact/cookie/v1": "c93630824487cce95ed28ba33123de9fe468be3e4151ad257cc8c0dd1e1d90cf",
		"pact/flow/v1":   "e9efca8a01c0427c838670f1c6ccd940bc13e2bdb44f3c0b7d70820a00de180e",
		"cauthy/sign/v1": "184fe579a0174e164d119120c37b847966e0b246428b19d570a3e0775b864f4b",
	} {
		if got := hex.EncodeToString(d.Labels[label]); got != want {
			t.Errorf("%s = %s", label, got)
		}
	}
	if d.X != "B_V_bXnOTf8w7eW80j8xDs0QqCE37TnfDWYAOJAQoWY" {
		t.Errorf("x = %s", d.X)
	}
	if d.KID != "dVpPrRtlQgOGn_9Q6DE2cgFRjUetrT2WPZCQyM48luc" {
		t.Errorf("kid = %s", d.KID)
	}
}

func TestAssertionIsDeterministicAndVerifies(t *testing.T) {
	k, _ := Parse(testKey)
	d := k.Derive()
	now := time.Unix(1793836800, 0)
	got := d.Assertion(testClient, "https://cauthy.api.example.com/v1/oauth/token", "00000000-0000-4000-8000-000000000000", now)
	want := "eyJhbGciOiJFZERTQSIsImtpZCI6ImRWcFByUnRsUWdPR25fOVE2REUyY2dGUmpVZXRyVDJXUFpDUXlNNDhsdWMifQ.eyJpc3MiOiJjbGllbnRfMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJzdWIiOiJjbGllbnRfMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJhdWQiOiJodHRwczovL2NhdXRoeS5hcGkuZXhhbXBsZS5jb20vdjEvb2F1dGgvdG9rZW4iLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDAiLCJpYXQiOjE3OTM4MzY4MDAsImV4cCI6MTc5MzgzNjkyMH0.pfjf9jH02BygIIzIVh84mksRjJyI3uVMC9Rl_x-FmkB3OLd6BwpiK7X8zELmiogrAfFZ6soioGYnMiHBi5nOCw"
	if got != want {
		t.Fatalf("Assertion = %s", got)
	}
	c, err := VerifyAssertion(d.Public, got)
	if err != nil || c.Iss != testClient || c.Exp-c.Iat != 120 {
		t.Fatalf("VerifyAssertion = %+v, %v", c, err)
	}
	if _, err := VerifyAssertion(d.Public, got[:len(got)-2]+"AA"); err == nil {
		t.Fatal("a changed signature verified")
	}
}

// An issuer is accepted only as a WHATWG URL serializes its origin, so Go,
// Node and the browser accept the same keys: ports and IP addresses written
// any other way are refused.
func TestIssuerIsWHATWGCanonical(t *testing.T) {
	for _, iss := range []string{
		"https://cauthy.api.example.com:",
		"https://cauthy.api.example.com:0443",
		"https://cauthy.api.example.com:08443",
		"https://cauthy.api.example.com:99999",
		"https://127.1",
		"https://0x7f.0.0.1",
		"https://1.2.3.04",
		"https://[0:0::1]",
		"https://[::FFFF:1.2.3.4]",
		"https://[::ffff:102:304]",
	} {
		if ValidIssuer(iss) {
			t.Errorf("%s: accepted", iss)
		}
	}
	for _, iss := range []string{"https://cauthy.api.example.com:8443", "https://1.2.3.4", "https://[2001:db8::1]:8443", "http://[::1]", "https://id.test:65535", "https://id.test:0"} {
		if !ValidIssuer(iss) {
			t.Errorf("%s: refused", iss)
		}
	}
}
