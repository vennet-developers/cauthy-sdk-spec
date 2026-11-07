// Package jws builds compact JWS tokens byte for byte, the broken ones
// included. It signs and never verifies; it is for the vector generator and
// for tests, so it panics instead of returning errors.
package jws

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // registers SHA-384 and SHA-512
	"encoding/base64"
	"encoding/json"
)

// Encode is base64url without padding, as JWS writes every segment.
func Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Segment is v as JSON, base64url-encoded. encoding/json sorts map keys, so
// the same value always gives the same segment.
func Segment(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return Encode(raw)
}

// SignRSA signs header.payload with RSASSA-PKCS1-v1_5. The signature depends
// only on the key and the input, so the generator's output is deterministic.
func SignRSA(key *rsa.PrivateKey, hash crypto.Hash, header, payload string) []byte {
	h := hash.New()
	h.Write([]byte(header + "." + payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, h.Sum(nil))
	if err != nil {
		panic(err)
	}
	return sig
}

// SignHMAC signs header.payload with HMAC, keyed with secret.
func SignHMAC(secret []byte, hash crypto.Hash, header, payload string) []byte {
	m := hmac.New(hash.New, secret)
	m.Write([]byte(header + "." + payload))
	return m.Sum(nil)
}

// Join writes the compact form: header.payload.signature.
func Join(header, payload string, sig []byte) string {
	return header + "." + payload + "." + Encode(sig)
}

// RS256 is the common case: header and claims as JSON, signed with key.
func RS256(key *rsa.PrivateKey, header, claims map[string]any) string {
	h, p := Segment(header), Segment(claims)
	return Join(h, p, SignRSA(key, crypto.SHA256, h, p))
}
