package verify_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/vectors"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/verify"
)

// TestVectors runs every vector in vectors/tokens.json against the reference
// verifier: the verdict and the reason must match exactly.
func TestVectors(t *testing.T) {
	f, jwks, err := vectors.Load(filepath.Join("..", "..", "..", "vectors"))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(f.LeewaySeconds)*time.Second != verify.DefaultLeeway || f.MaxTokenBytes != verify.MaxTokenBytes {
		t.Fatalf("the vectors assume leeway %ds and %d bytes; the verifier has %s and %d",
			f.LeewaySeconds, f.MaxTokenBytes, verify.DefaultLeeway, verify.MaxTokenBytes)
	}
	keys, err := verify.ParseJWKS(jwks)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			v, err := verify.New(verify.Config{
				Issuer: c.Config.Issuer, Issuers: c.Config.Issuers, Audience: c.Config.Audience, Tenant: c.Config.Tenant,
				AllowAnonymous: c.Config.AllowAnonymous,
			}, keys)
			if err != nil {
				t.Fatal(err)
			}
			_, err = v.Verify(context.Background(), c.Token, time.Unix(c.Now, 0))
			switch c.Expect {
			case "valid":
				if err != nil {
					t.Fatalf("%s: want valid, got %v", c.Description, err)
				}
			case "invalid":
				var e *verify.Error
				if !errors.As(err, &e) {
					t.Fatalf("%s: want %s, got %v", c.Description, c.Reason, err)
				}
				if string(e.Reason) != c.Reason {
					t.Fatalf("%s: want %s, got %s (%s)", c.Description, c.Reason, e.Reason, e.Detail)
				}
			default:
				t.Fatalf("expect is %q", c.Expect)
			}
		})
	}
}
