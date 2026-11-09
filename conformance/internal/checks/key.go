package checks

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/cauthykey"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
)

// RegisterKey registers the key.* checks. main calls it only with --key-env.
func RegisterKey(reg *check.Registry) {
	reg.Add(check.Check{ID: "key.parses", Group: "key", Level: check.Basic, Run: keyParses})
	reg.Add(check.Check{ID: "key.identity", Group: "key", Level: check.Basic, Run: keyIdentity})
	reg.Add(check.Check{ID: "key.signs_in", Group: "key", Level: check.Basic, Run: keySignsIn})
	reg.Add(check.Check{ID: "key.jwks", Group: "key", Level: check.Basic, NAPair: "key.signs_in", Run: keyJWKS})
}

func parsed(ctx *check.Ctx) (*cauthykey.Key, check.Result, bool) {
	k, err := cauthykey.Parse(ctx.Key)
	if err != nil {
		reason := ""
		if e, ok := err.(*cauthykey.Error); ok {
			reason = e.Reason
		}
		return nil, check.Fail("the key is refused: " + reason), false
	}
	if ctx.Cauthy != "" && strings.TrimRight(ctx.Cauthy, "/") != k.Issuer {
		return nil, check.Fail(fmt.Sprintf("the key names %s, the run's Cauthy is %s", k.Issuer, ctx.Cauthy)), false
	}
	return k, check.Result{}, true
}

func keyParses(ctx *check.Ctx) check.Result {
	k, r, ok := parsed(ctx)
	if !ok {
		return r
	}
	return check.Pass(fmt.Sprintf("issuer %s, client %s, kid %s", k.Issuer, k.ClientID, k.Derive().KID))
}

func keyIdentity(ctx *check.Ctx) check.Result {
	k, r, ok := parsed(ctx)
	if !ok {
		return r
	}
	d := k.Derive()
	hc := &http.Client{Timeout: 10 * time.Second}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {k.ClientID},
		"client_assertion_type": {cauthykey.AssertionType},
		"client_assertion":      {d.Assertion(k.ClientID, k.Issuer+"/v1/oauth/token", newUUID(), time.Now())}}
	res, err := hc.PostForm(k.Issuer+"/v1/oauth/token", form)
	if err != nil {
		return check.Fail("token: " + err.Error())
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return check.Fail(fmt.Sprintf("token: Cauthy answered %d to the key's assertion (kid %s)", res.StatusCode, d.KID))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		return check.Fail("token: no access_token")
	}
	req, _ := http.NewRequest(http.MethodGet, k.Issuer+"/v1/connect/self", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	sr, err := hc.Do(req)
	if err != nil {
		return check.Fail("self: " + err.Error())
	}
	defer sr.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(sr.Body, 64<<10))
	var self struct {
		Data struct {
			ClientID string `json:"client_id"`
			Key      struct {
				Kid string `json:"kid"`
			} `json:"key"`
		} `json:"data"`
	}
	if sr.StatusCode != 200 || json.Unmarshal(body, &self) != nil {
		return check.Fail(fmt.Sprintf("self: %d", sr.StatusCode))
	}
	if self.Data.ClientID != k.ClientID || self.Data.Key.Kid != d.KID {
		return check.Fail(fmt.Sprintf("self names client %s kid %s; the key is %s %s", self.Data.ClientID, self.Data.Key.Kid, k.ClientID, d.KID))
	}
	return check.Pass("Cauthy knows the key: client " + k.ClientID)
}

func keySignsIn(ctx *check.Ctx) check.Result {
	_, res, err := ctx.SignIn("key", false)
	if err != nil {
		return check.Fail(err.Error())
	}
	if res.Status != 200 {
		return check.Fail(fmt.Sprintf("sign-in answered %d", res.Status))
	}
	return check.Pass("signed in with nothing but the key")
}

func keyJWKS(ctx *check.Ctx) check.Result {
	if ctx.JWKSPath == "" {
		return check.NA("no --jwks-path: the backend has no contract")
	}
	k, r, ok := parsed(ctx)
	if !ok {
		return r
	}
	res, err := ctx.Client.GetOrigin(ctx.JWKSPath)
	if err != nil || res.Status != 200 {
		return check.Fail("the JWKS could not be read")
	}
	raw := string(res.Body)
	for _, m := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if strings.Contains(raw, m) {
			return check.Fail("the JWKS publishes private key material (" + m + ")")
		}
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	_ = json.Unmarshal(res.Body, &set)
	want := k.Derive().KID
	for _, j := range set.Keys {
		if j["kty"] == "OKP" && j["crv"] == "Ed25519" && j["kid"] == want {
			return check.Pass("the key is published: " + want)
		}
	}
	return check.Fail("the key's public half (kid " + want + ") is not in the JWKS")
}

// newUUID is a random UUID v4, the assertion's jti.
func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
