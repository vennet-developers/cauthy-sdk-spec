package fake

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/cauthykey"
)

func TestFakeCauthyAcceptsAKeyAndSaysWhoItIs(t *testing.T) {
	s := New(Knobs{})
	defer s.Close()
	base := s.StartCauthy("admin-token")
	key := s.IssueKey(base)
	k, err := cauthykey.Parse(key)
	if err != nil {
		t.Fatal(err)
	}
	d := k.Derive()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {k.ClientID},
		"client_assertion_type": {cauthykey.AssertionType},
		"client_assertion":      {d.Assertion(k.ClientID, base+"/v1/oauth/token", "11111111-1111-4111-8111-111111111111", time.Now())}}
	res, err := http.Post(base+"/v1/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("token: %v %v", res.StatusCode, err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&tok)
	req, _ := http.NewRequest("GET", base+"/v1/connect/self", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	res, err = http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("self: %v %v", res.StatusCode, err)
	}
	var self struct {
		Data struct {
			ClientID string                `json:"client_id"`
			Key      struct{ Kid string }  `json:"key"`
			Tenant   struct{ Slug string } `json:"tenant"`
		} `json:"data"`
	}
	_ = json.NewDecoder(res.Body).Decode(&self)
	if self.Data.ClientID != k.ClientID || self.Data.Key.Kid != d.KID || self.Data.Tenant.Slug != Tenant {
		t.Fatalf("self = %+v", self.Data)
	}
	// The same jti twice is a replay.
	res, _ = http.Post(base+"/v1/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if res.StatusCode != 401 {
		t.Fatalf("replay answered %d", res.StatusCode)
	}
}
