package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/jws"
)

// The test-only keys, by kid. Their files live in vectors/keys as private JWKs.
const (
	KidA        = "test-only-a"        // the current signing key
	KidB        = "test-only-b"        // the previous key, still published (rotation)
	KidWeak     = "test-only-weak"     // 1024 bits: published, never accepted
	KidAttacker = "test-only-attacker" // never published as a signing key
	KidEnc      = "test-only-enc"      // the attacker's key, published with use "enc"
)

// keySpecs is every key file and its size.
var keySpecs = []struct {
	kid  string
	bits int
}{{KidA, 2048}, {KidB, 2048}, {KidAttacker, 2048}, {KidWeak, 1024}}

const keyComment = "TEST ONLY. A key for the cauthy-sdk-spec vectors, published on purpose. Never use it to sign anything real."

// privateJWK is a private RSA key as a JWK (RFC 7518 §6.3), with a comment
// that says it is a test key.
type privateJWK struct {
	Comment string `json:"comment"`
	Kty     string `json:"kty"`
	Kid     string `json:"kid"`
	N       string `json:"n"`
	E       string `json:"e"`
	D       string `json:"d"`
	P       string `json:"p"`
	Q       string `json:"q"`
}

func b64int(i *big.Int) string { return jws.Encode(i.Bytes()) }

func unb64int(s string) (*big.Int, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

// Keys are the test-only keys by kid.
type Keys map[string]*rsa.PrivateKey

// MakeKeys writes every key file missing in dir. It never replaces one:
// replacing a key changes every token in the vectors.
func MakeKeys(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, spec := range keySpecs {
		path := filepath.Join(dir, spec.kid+".jwk.json")
		if _, err := os.Stat(path); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		key, err := rsa.GenerateKey(rand.Reader, spec.bits)
		if err != nil {
			return err
		}
		raw, _ := json.MarshalIndent(privateJWK{
			Comment: keyComment, Kty: "RSA", Kid: spec.kid,
			N: b64int(key.N), E: b64int(big.NewInt(int64(key.E))), D: b64int(key.D),
			P: b64int(key.Primes[0]), Q: b64int(key.Primes[1]),
		}, "", "  ")
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// LoadKeys reads every key file in dir.
func LoadKeys(dir string) (Keys, error) {
	keys := Keys{}
	for _, spec := range keySpecs {
		raw, err := os.ReadFile(filepath.Join(dir, spec.kid+".jwk.json"))
		if err != nil {
			return nil, err
		}
		var j privateJWK
		if err := json.Unmarshal(raw, &j); err != nil {
			return nil, fmt.Errorf("%s: %w", spec.kid, err)
		}
		if j.Comment != keyComment || j.Kid != spec.kid || j.Kty != "RSA" {
			return nil, fmt.Errorf("%s: not a test-only RSA key file", spec.kid)
		}
		var ints [5]*big.Int
		for i, s := range []string{j.N, j.E, j.D, j.P, j.Q} {
			if ints[i], err = unb64int(s); err != nil {
				return nil, fmt.Errorf("%s: %w", spec.kid, err)
			}
		}
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: ints[0], E: int(ints[1].Int64())},
			D:         ints[2], Primes: []*big.Int{ints[3], ints[4]},
		}
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", spec.kid, err)
		}
		key.Precompute()
		if key.N.BitLen() != spec.bits {
			return nil, fmt.Errorf("%s: %d bits, want %d", spec.kid, key.N.BitLen(), spec.bits)
		}
		keys[spec.kid] = key
	}
	return keys, nil
}
