package apigen

import "testing"

func TestGoName(t *testing.T) {
	for in, want := range map[string]string{
		"client_id":                 "ClientID",
		"redirect_uris":             "RedirectURIs",
		"jwks_uri":                  "JWKSURI",
		"mfa_token":                 "MFAToken",
		"user_ids":                  "UserIDs",
		"emailVerified":             "EmailVerified",
		"allow_persistent_sessions": "AllowPersistentSessions",
		"OAuthClient":               "OAuthClient",
		"x-cauthy-flow":             "XCauthyFlow",
		"2fa":                       "X2fa",
		"*":                         "X",
	} {
		if got := GoName(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}
