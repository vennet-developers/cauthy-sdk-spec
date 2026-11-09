package checks

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/cauthykey"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

// The test key: secret bytes 00..1f, a test value.
const keyChecksTestKey = "cauthy1.aHR0cHM6Ly9jYXV0aHkuYXBpLmV4YW1wbGUuY29t.Y2xpZW50XzAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.AAvYhJZh"

// runOne registers the checks with register, runs the one named id and
// answers its result.
func runOne(t *testing.T, ctx *check.Ctx, register func(*check.Registry), id string) check.Result {
	t.Helper()
	reg := &check.Registry{}
	register(reg)
	for _, c := range reg.All() {
		if c.ID == id {
			return c.Run(ctx)
		}
	}
	t.Fatalf("no check %s", id)
	return check.Result{}
}

func TestKeyChecksPassOnAKeyBackend(t *testing.T) {
	ctx, srv := ctxFor(t, fake.Knobs{Strict: true})
	base := srv.StartCauthy("admin-token")
	ctx.Cauthy = base
	ctx.Key = srv.IssueKey(base)
	for _, id := range []string{"key.parses", "key.identity", "key.signs_in"} {
		if r := runOne(t, ctx, RegisterKey, id); r.Status != check.StatusPass {
			t.Errorf("%s: %s %s", id, r.Status, r.Detail)
		}
	}
	if r := runOne(t, ctx, RegisterKey, "key.parses"); strings.Contains(r.Detail, ctx.Key) {
		t.Fatalf("the report shows the key: %s", r.Detail)
	}
}

func TestKeyParsesNamesTheReason(t *testing.T) {
	ctx := &check.Ctx{Key: "cauthy1.YQ.Yg"}
	r := runOne(t, ctx, RegisterKey, "key.parses")
	if r.Status != check.StatusFail || !strings.Contains(r.Detail, "key_format") {
		t.Fatalf("%+v", r)
	}
}

func TestKeyIdentityFailsOnAnotherCauthy(t *testing.T) {
	_, srv := ctxFor(t, fake.Knobs{Strict: true})
	base := srv.StartCauthy("admin-token")
	_, other := ctxFor(t, fake.Knobs{Strict: true})
	otherBase := other.StartCauthy("admin-token")
	ctx := &check.Ctx{Cauthy: base, Key: other.IssueKey(otherBase)}
	for _, id := range []string{"key.parses", "key.identity"} {
		if r := runOne(t, ctx, RegisterKey, id); r.Status != check.StatusFail {
			t.Fatalf("%s: a key for another Cauthy passed: %+v", id, r)
		}
	}
}

func TestKeyIdentityFailsWhenCauthyDoesNotKnowTheKey(t *testing.T) {
	_, srv := ctxFor(t, fake.Knobs{Strict: true})
	base := srv.StartCauthy("admin-token")
	// A well-formed key for this Cauthy that it never registered.
	key, err := cauthykey.Compose(base, fake.ClientID, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatal(err)
	}
	r := runOne(t, &check.Ctx{Cauthy: base, Key: key}, RegisterKey, "key.identity")
	if r.Status != check.StatusFail || !strings.Contains(r.Detail, "401") {
		t.Fatalf("%+v", r)
	}
}

func TestKeyJWKSIsNAWithoutJWKSPath(t *testing.T) {
	ctx := &check.Ctx{Key: "x"}
	if r := runOne(t, ctx, RegisterKey, "key.jwks"); r.Status != check.StatusNA {
		t.Fatalf("%+v", r)
	}
}

func TestKeyJWKS(t *testing.T) {
	k, err := cauthykey.Parse(keyChecksTestKey)
	if err != nil {
		t.Fatal(err)
	}
	d := k.Derive()
	published := `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + d.X + `","kid":"` + d.KID + `","alg":"EdDSA","use":"sig"}]}`
	for _, c := range []struct {
		name, body, status string
	}{
		{"published", published, check.StatusPass},
		{"another key", `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA","kid":"other"}]}`, check.StatusFail},
		{"private member", `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + d.X + `","kid":"` + d.KID + `","d":"AAAA"}]}`, check.StatusFail},
	} {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/pact-jwks.json" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(c.body))
		}))
		ctx := &check.Ctx{Key: keyChecksTestKey, JWKSPath: "/.well-known/pact-jwks.json", Client: client.New(origin.URL+"/api/auth", origin.URL)}
		if r := runOne(t, ctx, RegisterKey, "key.jwks"); r.Status != c.status {
			t.Errorf("%s: %s %s", c.name, r.Status, r.Detail)
		}
		origin.Close()
	}
}
