package fake

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// adminDo calls the fake Cauthy as its admin.
func adminDo(t *testing.T, base, token, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, base+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-Key", Tenant)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestTheFakeCauthyNeedsItsToken(t *testing.T) {
	s, _ := newClient(t, Knobs{})
	base := s.StartCauthy("admin-token")
	if code, _ := adminDo(t, base, "wrong", "GET", "/v1/settings/auth", nil); code != 401 {
		t.Fatalf("%d", code)
	}
	if code, out := adminDo(t, base, "admin-token", "GET", "/v1/settings/auth", nil); code != 200 || out["data"].(map[string]any)["allow_password"] != true {
		t.Fatalf("%d %v", code, out)
	}
}

func TestMethodsFollowTheSettingsAtOnce(t *testing.T) {
	s, c := newClient(t, Knobs{})
	base := s.StartCauthy("admin-token")
	if m := mustGet(t, c, "/methods").JSON; m["signUp"] != true || m["magicLink"] != false || m["passkey"] != false {
		t.Fatalf("defaults: %v", m)
	}
	if code, _ := adminDo(t, base, "admin-token", "PUT", "/v1/settings/auth", map[string]any{"allow_signup": false, "allow_magic_link": true, "allow_passkeys": true}); code != 200 {
		t.Fatalf("%d", code)
	}
	if m := mustGet(t, c, "/methods").JSON; m["signUp"] != false || m["magicLink"] != true || m["passkey"] != true {
		t.Fatalf("after the switch: %v", m)
	}
	adminDo(t, base, "admin-token", "PATCH", "/v1/oauth/clients/"+ClientID, map[string]any{"allow_persistent_sessions": true})
	if m := mustGet(t, c, "/methods").JSON; m["persistentSessions"] != true {
		t.Fatalf("persistent: %v", m)
	}
}

func TestStaleSettingsNeverChange(t *testing.T) {
	s, c := newClient(t, Knobs{StaleSettings: true})
	base := s.StartCauthy("admin-token")
	adminDo(t, base, "admin-token", "PUT", "/v1/settings/auth", map[string]any{"allow_signup": false})
	if m := mustGet(t, c, "/methods").JSON; m["signUp"] != true {
		t.Fatalf("a stale backend still says signUp: %v", m)
	}
	if s.Setting("allow_signup") != false {
		t.Fatal("the fake Cauthy itself changed")
	}
}

func TestCauthyKeepsOneWayIn(t *testing.T) {
	s, _ := newClient(t, Knobs{})
	base := s.StartCauthy("admin-token")
	if code, out := adminDo(t, base, "admin-token", "PUT", "/v1/settings/auth", map[string]any{"allow_password": false}); code != 409 {
		t.Fatalf("%d %v", code, out)
	}
}

func TestSignUpFollowsTheTenant(t *testing.T) {
	s, c := newClient(t, Knobs{})
	base := s.StartCauthy("admin-token")
	body := map[string]any{"email": "new@example.com", "password": "Long-enough-1"}
	if r := mustPost(t, c, "/sign-up/email", body, nil); r.Status != 200 || r.JSON["status"] != "signed_in" {
		t.Fatalf("open: %d %v", r.Status, r.JSON)
	}
	adminDo(t, base, "admin-token", "PUT", "/v1/settings/auth", map[string]any{"confirm_email": true})
	body["email"] = "held@example.com"
	if r := mustPost(t, c, "/sign-up/email", body, nil); r.Status != 200 || r.JSON["status"] != "verification_required" || len(r.SetCookies) != 0 {
		t.Fatalf("confirm: %d %v", r.Status, r.JSON)
	}
	adminDo(t, base, "admin-token", "PUT", "/v1/settings/auth", map[string]any{"allow_signup": false})
	body["email"] = "closed@example.com"
	if r := mustPost(t, c, "/sign-up/email", body, nil); r.Status != 403 {
		t.Fatalf("closed: %d %v", r.Status, r.JSON)
	}
	if got := s.Accounts(); len(got) != 2 {
		t.Fatalf("accounts: %v", got)
	}
	_, list := adminDo(t, base, "admin-token", "GET", "/v1/users?q=held@example.com", nil)
	id := list["data"].([]any)[0].(map[string]any)["id"].(string)
	if code, _ := adminDo(t, base, "admin-token", "DELETE", "/v1/users/"+id, nil); code != 204 || len(s.Accounts()) != 1 {
		t.Fatalf("delete: %d %v", code, s.Accounts())
	}
}

func TestPasswordsOffRefusesAPassword(t *testing.T) {
	s, c := newClient(t, Knobs{})
	base := s.StartCauthy("admin-token")
	adminDo(t, base, "admin-token", "PUT", "/v1/settings/auth", map[string]any{"allow_magic_link": true, "allow_password": false})
	r := mustPost(t, c, "/sign-in/email", map[string]any{"email": s.Email, "password": s.Password}, nil)
	if r.Status != 403 || r.JSON["error"].(map[string]any)["code"] != "password_disabled" {
		t.Fatalf("%d %v", r.Status, r.JSON)
	}
}
