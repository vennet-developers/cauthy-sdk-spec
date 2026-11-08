package apigen

import (
	"strings"
	"unicode"
)

// initialisms are written in capitals, as Go names them.
var initialisms = map[string]string{
	"acs": "ACS", "api": "API", "css": "CSS", "html": "HTML", "http": "HTTP", "https": "HTTPS",
	"id": "ID", "ids": "IDs", "ip": "IP", "ips": "IPs", "json": "JSON", "jwk": "JWK", "jwks": "JWKS",
	"jwt": "JWT", "mfa": "MFA", "oidc": "OIDC", "otp": "OTP", "pkce": "PKCE", "saml": "SAML",
	"scim": "SCIM", "sid": "SID", "sms": "SMS", "sso": "SSO", "totp": "TOTP", "ttl": "TTL",
	"ui": "UI", "uri": "URI", "uris": "URIs", "url": "URL", "urls": "URLs", "uuid": "UUID",
}

// GoName turns a JSON field or schema name into an exported Go identifier:
// client_id is ClientID, redirect_uris RedirectURIs, emailVerified EmailVerified.
func GoName(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	var b strings.Builder
	for _, p := range parts {
		if up, ok := initialisms[strings.ToLower(p)]; ok {
			b.WriteString(up)
			continue
		}
		r := []rune(p)
		r[0] = unicode.ToUpper(r[0])
		b.WriteString(string(r))
	}
	name := b.String()
	if name == "" || unicode.IsDigit([]rune(name)[0]) {
		name = "X" + name
	}
	return name
}
