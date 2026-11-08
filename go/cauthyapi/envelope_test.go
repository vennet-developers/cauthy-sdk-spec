package cauthyapi

import (
	"encoding/json"
	"testing"
)

func TestSettingsDecode(t *testing.T) {
	var got Data[WorkspaceAuthSettings]
	if err := json.Unmarshal([]byte(`{"data":{"allow_signup":true,"confirm_email":false,"verify_grace_days":3}}`), &got); err != nil {
		t.Fatal(err)
	}
	s := got.Data
	if s.AllowSignup == nil || !*s.AllowSignup || s.ConfirmEmail == nil || *s.ConfirmEmail || s.VerifyGraceDays == nil || *s.VerifyGraceDays != 3 {
		t.Fatalf("%+v", s)
	}
}

func TestErrorDecode(t *testing.T) {
	var e ApiError
	raw := `{"errors":[{"code":"invalid_credentials","message":"invalid email or password"}],"request_id":"r1","status":401,"status_text":"Unauthorized"}`
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	if len(e.Errors) != 1 || e.Errors[0].Code != "invalid_credentials" || e.Status != 401 || e.StatusText != "Unauthorized" {
		t.Fatalf("%+v", e)
	}
}

func TestListDecode(t *testing.T) {
	var got List[OAuthClient]
	if err := json.Unmarshal([]byte(`{"data":[{"client_id":"acme-crm","allow_persistent_sessions":true}],"total_count":1}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.TotalCount != 1 || got.Data[0].ClientID == nil || *got.Data[0].ClientID != "acme-crm" {
		t.Fatalf("%+v", got)
	}
}
