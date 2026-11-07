package verify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
	weakKey *rsa.PrivateKey
)

// keys answers a 2048-bit and a 1024-bit key, made once per test run.
func keys(t *testing.T) (strong, weak *rsa.PrivateKey) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if testKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if weakKey, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
			panic(err)
		}
	})
	return testKey, weakKey
}

// jwkJSON renders key as a JWKS member with the given fields.
func jwkJSON(key *rsa.PublicKey, kty, use, alg, kid string) string {
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return fmt.Sprintf(`{"kty":%q,"use":%q,"alg":%q,"kid":%q,"n":%q,"e":%q}`, kty, use, alg, kid, n, e)
}

func TestParseJWKSKeepsOnlyUsableKeys(t *testing.T) {
	strong, weak := keys(t)
	set, err := ParseJWKS([]byte(`{"keys":[` +
		jwkJSON(&strong.PublicKey, "RSA", "sig", "RS256", "good") + `,` +
		jwkJSON(&strong.PublicKey, "RSA", "", "", "bare") + `,` +
		jwkJSON(&strong.PublicKey, "RSA", "enc", "RS256", "enc") + `,` +
		jwkJSON(&strong.PublicKey, "RSA", "sig", "RS384", "rs384") + `,` +
		jwkJSON(&strong.PublicKey, "EC", "sig", "RS256", "ec") + `,` +
		jwkJSON(&strong.PublicKey, "RSA", "sig", "RS256", "") + `,` +
		jwkJSON(&weak.PublicKey, "RSA", "sig", "RS256", "weak") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, kid := range []string{"good", "bare"} {
		if k, err := set.Key(ctx, kid); err != nil || k.N.Cmp(strong.N) != 0 {
			t.Errorf("%s: %v", kid, err)
		}
	}
	for _, kid := range []string{"enc", "rs384", "ec", "", "absent"} {
		if _, err := set.Key(ctx, kid); !errors.Is(err, ErrUnknownKid) {
			t.Errorf("%s: want ErrUnknownKid, got %v", kid, err)
		}
	}
	if _, err := set.Key(ctx, "weak"); !errors.Is(err, ErrWeakKey) {
		t.Errorf("weak: want ErrWeakKey, got %v", err)
	}
}

func TestParseJWKSRefusesBadSets(t *testing.T) {
	strong, _ := keys(t)
	dup := jwkJSON(&strong.PublicKey, "RSA", "sig", "RS256", "same")
	for name, raw := range map[string]string{
		"not json":      `nope`,
		"no keys":       `{}`,
		"duplicate kid": `{"keys":[` + dup + `,` + dup + `]}`,
	} {
		if _, err := ParseJWKS([]byte(raw)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestParseJWKSSkipsMalformedMembersAndHonoursKeyOps(t *testing.T) {
	strong, _ := keys(t)
	n := base64.RawURLEncoding.EncodeToString(strong.N.Bytes())
	good := jwkJSON(&strong.PublicKey, "RSA", "sig", "RS256", "good")
	member := func(extra string) string {
		return fmt.Sprintf(`{"kty":"RSA","kid":"k","n":%q,"e":"AQAB"%s}`, n, extra)
	}
	raw := `{"keys":[` + good + `,"not an object",{"kty":7},` +
		strings.Replace(member(``), `"k"`, `"upper"`, 1) + `,` +
		`{"KTY":"RSA","KID":"loud","n":"` + n + `","e":"AQAB"},` +
		strings.Replace(member(`,"key_ops":["sign"]`), `"k"`, `"signonly"`, 1) + `,` +
		strings.Replace(member(`,"key_ops":["verify"]`), `"k"`, `"verifyonly"`, 1) + `,` +
		strings.Replace(member(`,"kid":1`), `"k"`, `"dupe"`, 1) + `]}`
	set, err := ParseJWKS([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, kid := range []string{"good", "upper", "verifyonly"} {
		if _, err := set.Key(ctx, kid); err != nil {
			t.Errorf("%s: %v", kid, err)
		}
	}
	for _, kid := range []string{"loud", "signonly", "dupe", "k"} {
		if _, err := set.Key(ctx, kid); !errors.Is(err, ErrUnknownKid) {
			t.Errorf("%s: want ErrUnknownKid, got %v", kid, err)
		}
	}
}

func TestParseJWKSRefusesAnEmptySet(t *testing.T) {
	for name, raw := range map[string]string{
		"empty array":     `{"keys":[]}`,
		"only unusable":   `{"keys":[{"kty":"EC"}]}`,
		"keys not a list": `{"keys":{}}`,
	} {
		if _, err := ParseJWKS([]byte(raw)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
