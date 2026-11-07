package verify

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// MinKeyBits is the smallest RSA key a token may be signed with. Cauthy's
// keys are 2048 bits.
const MinKeyBits = 2048

var (
	// ErrUnknownKid: no usable key in the issuer's set has the token's kid.
	ErrUnknownKid = errors.New("verify: no signing key with that kid")
	// ErrWeakKey: the key is smaller than MinKeyBits.
	ErrWeakKey = errors.New("verify: the signing key is smaller than 2048 bits")
)

// Keys answers the public key a token names by its kid. It answers
// ErrUnknownKid or ErrWeakKey (possibly wrapped) when it cannot.
type Keys interface {
	Key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// StaticKeys is a parsed JWK Set.
type StaticKeys struct {
	byKid map[string]*rsa.PublicKey
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ParseJWKS reads a JWK Set. Only keys a Cauthy token can be signed with are
// kept: kty RSA, use sig or absent, alg RS256 or absent, a kid, a sound
// modulus and exponent. Anything else is skipped, so a token naming it reads
// as an unknown kid. Two usable keys with one kid make the set invalid.
func ParseJWKS(raw []byte) (*StaticKeys, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("verify: JWKS: %w", err)
	}
	if set.Keys == nil {
		return nil, errors.New("verify: JWKS has no keys member")
	}
	k := &StaticKeys{byKid: map[string]*rsa.PublicKey{}}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || (j.Use != "" && j.Use != "sig") || (j.Alg != "" && j.Alg != "RS256") || j.Kid == "" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(j.N)
		e, errE := base64.RawURLEncoding.DecodeString(j.E)
		if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			continue
		}
		exp := int(new(big.Int).SetBytes(e).Int64())
		if exp < 3 || exp%2 == 0 {
			continue
		}
		if _, dup := k.byKid[j.Kid]; dup {
			return nil, fmt.Errorf("verify: JWKS has two keys with kid %q", j.Kid)
		}
		k.byKid[j.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	}
	return k, nil
}

// Key answers the key with kid.
func (k *StaticKeys) Key(_ context.Context, kid string) (*rsa.PublicKey, error) {
	key, ok := k.byKid[kid]
	if !ok {
		return nil, ErrUnknownKid
	}
	if key.N.BitLen() < MinKeyBits {
		return nil, ErrWeakKey
	}
	return key, nil
}
