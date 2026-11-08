package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"maps"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/jws"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/vectors"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/verify"
)

// The fixed world every case lives in. All of it is fictitious.
const (
	Now          = 1767225600 // 2026-01-01T00:00:00Z
	Issuer       = "https://auth.example.com"
	CustomIssuer = "https://login.acme.example" // a workspace's custom domain
	Audience     = "cauthy"
	Tenant       = "8a6e0804-2bd0-4672-b79a-d97027f5f2a1"
	OtherTenant  = "3f2a9c41-7d4b-4e8a-a1c2-5b6d7e8f9a0b"
	Subject      = "5c1b2f4e-9a3d-4b7e-8c6f-0d1e2f3a4b5c"
	Client       = "9d8c7b6a-5f4e-4d3c-8b2a-1f0e9d8c7b6a"
	JTI          = "e0f1a2b3-c4d5-4e6f-8a9b-0c1d2e3f4a5b"
)

var config = vectors.Config{Issuer: Issuer, Audience: Audience, Tenant: Tenant}

// person is the claims of a person's access token as Cauthy issues it: issued
// a minute before Now, living 15 minutes.
func person() map[string]any {
	return map[string]any{
		"iss": Issuer, "aud": []string{Audience}, "sub": Subject, "tid": Tenant, "jti": JTI,
		"iat": Now - 60, "exp": Now + 840, "auth_time": Now - 60,
		"roles": []string{"member"}, "email": "ada@example.com", "email_verified": true,
	}
}

// header is Cauthy's header for kid.
func header(kid string) map[string]any {
	return map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}
}

// with answers a copy of m with the pairs set; a nil value removes the key.
func with(m map[string]any, kv ...any) map[string]any {
	out := maps.Clone(m)
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(out, kv[i].(string))
		} else {
			out[kv[i].(string)] = kv[i+1]
		}
	}
	return out
}

// null is a claim whose value is JSON null (a nil in with removes the claim).
type null struct{}

func (null) MarshalJSON() ([]byte, error) { return []byte("null"), nil }

// number is a claim written exactly as given: a JSON number in a syntax
// json.Marshal would not choose, such as 1.8e9 or 1800000000.0.
type number string

func (n number) MarshalJSON() ([]byte, error) { return []byte(n), nil }

// Cases answers every case, in the order of the rules.
func Cases(k Keys) []vectors.Case {
	a := k[KidA]
	valid := func(name, rule, desc, token string) vectors.Case {
		return vectors.Case{Name: name, Rule: rule, Description: desc, Token: token, Now: Now, Config: config, Expect: "valid"}
	}
	invalid := func(name, rule, desc, token string, reason verify.Reason) vectors.Case {
		return vectors.Case{Name: name, Rule: rule, Description: desc, Token: token, Now: Now, Config: config, Expect: "invalid", Reason: string(reason)}
	}
	signed := func(claims map[string]any) string { return jws.RS256(a, header(KidA), claims) }
	good := signed(person())
	parts := strings.Split(good, ".")

	// raw signs a header and payload given as bytes, so they can be anything.
	raw := func(h, p []byte) string {
		hs, ps := jws.Encode(h), jws.Encode(p)
		return jws.Join(hs, ps, jws.SignRSA(a, crypto.SHA256, hs, ps))
	}
	// withAlg signs person() with a's key under another algorithm name.
	withAlg := func(alg string, hash crypto.Hash) string {
		hs, ps := jws.Segment(with(header(KidA), "alg", alg)), jws.Segment(person())
		return jws.Join(hs, ps, jws.SignRSA(a, hash, hs, ps))
	}
	// pemOfA is a's public key as PEM text: the HMAC secret of the classic
	// key-confusion attack.
	spki, _ := x509.MarshalPKIXPublicKey(&a.PublicKey)
	pemOfA := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	hsHeader, hsPayload := jws.Segment(with(header(KidA), "alg", "HS256")), jws.Segment(person())
	tampered := jws.Segment(with(person(), "roles", []string{"owner"}))
	agent := with(person(), "aud", []string{"https://mcp.example.com"}, "scope", "crm:read", "client_id", "mcp-agent", "auth_time", nil)
	system := with(person(), "sub", Client, "roles", []string{}, "email", nil, "email_verified", nil, "auth_time", nil, "sys", "acme-crm")
	guest := with(person(), "email", nil, "email_verified", nil, "anon", true)
	// client is a client's own token, from a client_credentials grant: sub the
	// client's internal id, its roles, no email, token_use and its public id.
	client := with(person(), "sub", Client, "roles", []string{"invoices:read"}, "email", nil, "email_verified", nil, "auth_time", nil,
		"token_use", "client", "client_id", "acme-billing")
	attackerJWK := publicOf(k, KidAttacker, KidA, "sig")
	customDomain := signed(with(person(), "iss", CustomIssuer))
	// dupPayload is person() with sub written twice, the first one another's.
	personJSON, _ := json.Marshal(person())
	dupPayload := []byte(`{"sub":"` + OtherTenant + `",` + string(personJSON[1:]))
	dupHeader := []byte(`{"alg":"none","alg":"RS256","kid":"` + KidA + `","typ":"JWT"}`)
	shortSig := jws.Join(parts[0], parts[1], make([]byte, 10))
	longSig := jws.Join(parts[0], parts[1], make([]byte, 300))
	mid := len(parts[2]) / 2

	cases := []vectors.Case{
		valid("valid/person", "-", "A person's token as Cauthy issues it", good),
		valid("valid/previous-key", "R5", "Signed with the previous key, still published during a rotation", jws.RS256(k[KidB], header(KidB), person())),
		valid("valid/typ-absent", "R4", "No typ header: a verifier does not require one", jws.RS256(a, with(header(KidA), "typ", nil), person())),
		valid("valid/typ-at-jwt", "R4", "typ at+jwt, in lower case", jws.RS256(a, with(header(KidA), "typ", "at+jwt"), person())),
		valid("valid/typ-lower-case", "R4", "typ jwt in lower case: typ is compared without regard to case", jws.RS256(a, with(header(KidA), "typ", "jwt"), person())),
		valid("valid/aud-string", "R10", "aud as a single string", signed(with(person(), "aud", Audience))),
		valid("valid/aud-among-several", "R10", "aud lists the audience among others", signed(with(person(), "aud", []string{"https://other.example.com", Audience}))),
		valid("valid/roles-null", "R8", "roles is null: no roles", signed(with(person(), "roles", null{}))),
		valid("valid/unknown-claims", "R8", "Claims the rules do not name are ignored", signed(with(person(), "keep", true, "custom", map[string]any{"segments": []string{"beta"}}, "x_future", "ignored"))),
		valid("valid/exp-inside-leeway", "R11", "exp passed 29 seconds ago, inside the 30-second leeway", signed(with(person(), "exp", Now-29))),
		valid("valid/nbf-inside-leeway", "R11", "nbf is 30 seconds ahead, at the edge of the leeway", signed(with(person(), "nbf", Now+30))),
		valid("valid/iat-inside-leeway", "R11", "iat is 30 seconds ahead, at the edge of the leeway", signed(with(person(), "iat", Now+30))),
		func() vectors.Case {
			c := valid("valid/anonymous-allowed", "R14", "A guest's token where the backend allows guests", signed(guest))
			c.Config.AllowAnonymous = true
			return c
		}(),
		func() vectors.Case {
			c := valid("valid/client-token-allowed", "R13", "A client's own token where the backend serves machines (allow_client_tokens)", signed(client))
			c.Config.AllowClientTokens = true
			return c
		}(),
		valid("valid/azp", "R8", "A person's token issued through a client: azp names it", signed(with(person(), "azp", "acme-web"))),
		func() vectors.Case {
			c := valid("valid/second-issuer", "R9", "iss is the workspace's custom domain, listed in issuers beside the configured issuer", customDomain)
			c.Config.Issuers = []string{CustomIssuer}
			return c
		}(),
		valid("valid/size-at-limit", "R1", "As long as a token may be", sized(a, false)),

		invalid("size/too-large", "R1", "One byte over the limit, otherwise valid", sized(a, true), verify.TooLarge),

		invalid("shape/two-segments", "R2", "header.payload with no signature segment", parts[0]+"."+parts[1], verify.Malformed),
		invalid("shape/four-segments", "R2", "A fourth segment", good+".e30", verify.Malformed),
		invalid("shape/padded-signature", "R2", "The signature segment carries base64 padding", good+"==", verify.Malformed),
		invalid("shape/header-not-json", "R2", "The header is not JSON", raw([]byte("not json"), []byte(`{}`)), verify.Malformed),
		invalid("shape/header-array", "R2", "The header is a JSON array", raw([]byte(`["RS256"]`), []byte(`{}`)), verify.Malformed),
		invalid("shape/payload-not-json", "R2", "The payload is not JSON, under a valid signature", raw([]byte(`{"alg":"RS256","kid":"`+KidA+`","typ":"JWT"}`), []byte("not json")), verify.Malformed),
		invalid("shape/newline-in-signature", "R2", "A line break inside the signature segment, which some base64 decoders skip", parts[0]+"."+parts[1]+"."+parts[2][:mid]+"\n"+parts[2][mid:], verify.Malformed),
		invalid("shape/trailing-crlf", "R2", "A carriage return and a line feed after the token", good+"\r\n", verify.Malformed),
		invalid("shape/duplicate-header-key", "R2", "alg appears twice in the header, under a valid signature", raw(dupHeader, personJSON), verify.Malformed),
		invalid("shape/duplicate-claim", "R2", "sub appears twice in the payload, under a valid signature", raw([]byte(`{"alg":"RS256","kid":"`+KidA+`","typ":"JWT"}`), dupPayload), verify.Malformed),

		invalid("alg/none", "R3", "alg none with an empty signature", jws.Segment(with(header(KidA), "alg", "none"))+"."+parts[1]+".", verify.AlgNotAllowed),
		invalid("alg/missing", "R3", "No alg header", jws.RS256(a, with(header(KidA), "alg", nil), person()), verify.AlgNotAllowed),
		invalid("alg/hs256-key-confusion", "R3", "HS256 keyed with the published public key's PEM", jws.Join(hsHeader, hsPayload, jws.SignHMAC(pemOfA, crypto.SHA256, hsHeader, hsPayload)), verify.AlgNotAllowed),
		invalid("alg/rs384", "R3", "RS384 with the real key: Cauthy signs RS256 only", withAlg("RS384", crypto.SHA384), verify.AlgNotAllowed),
		invalid("alg/rs512", "R3", "RS512 with the real key", withAlg("RS512", crypto.SHA512), verify.AlgNotAllowed),
		invalid("alg/ps256", "R3", "PS256 named in the header", withAlg("PS256", crypto.SHA256), verify.AlgNotAllowed),
		invalid("alg/es256", "R3", "ES256 named in the header", jws.Join(jws.Segment(with(header(KidA), "alg", "ES256")), parts[1], make([]byte, 64)), verify.AlgNotAllowed),
		invalid("alg/lower-case", "R3", "alg rs256 in lower case: the name is compared exactly", jws.RS256(a, with(header(KidA), "alg", "rs256"), person()), verify.AlgNotAllowed),

		invalid("header/crit", "R4", "A crit header the verifier cannot honour", jws.RS256(a, with(header(KidA), "crit", []string{"exp"}), person()), verify.UnsupportedHeader),
		invalid("header/typ-webhook", "R4", "typ cauthy-webhook+jwt: a webhook's JWT is not an access token", jws.RS256(a, with(header(KidA), "typ", "cauthy-webhook+jwt"), person()), verify.UnsupportedHeader),
		invalid("header/typ-not-string", "R4", "typ is a number", jws.RS256(a, with(header(KidA), "typ", 1), person()), verify.UnsupportedHeader),

		invalid("kid/missing", "R5", "No kid header", jws.RS256(a, with(header(KidA), "kid", nil), person()), verify.MissingKid),
		invalid("kid/empty", "R5", "An empty kid", jws.RS256(a, header(""), person()), verify.MissingKid),
		invalid("kid/number", "R5", "kid is a number", jws.RS256(a, with(header(KidA), "kid", 1), person()), verify.MissingKid),
		invalid("kid/unknown", "R5", "A kid the issuer never published", jws.RS256(k[KidAttacker], header(KidAttacker), person()), verify.UnknownKid),
		invalid("kid/jku-ignored", "R4", "jku points at the attacker's set; it is never fetched", jws.RS256(k[KidAttacker], with(header(KidAttacker), "jku", "https://attacker.example.com/jwks.json"), person()), verify.UnknownKid),
		invalid("kid/encryption-key", "R5", "The kid names a published key whose use is enc", jws.RS256(k[KidAttacker], header(KidEnc), person()), verify.UnknownKid),
		invalid("kid/weak-key", "R5", "The kid names a published 1024-bit key", jws.RS256(k[KidWeak], header(KidWeak), person()), verify.WeakKey),

		invalid("sig/forged-known-kid", "R6", "Signed by another key under the real kid", jws.RS256(k[KidAttacker], header(KidA), person()), verify.BadSignature),
		invalid("sig/embedded-jwk", "R4", "The header carries the signer's own key; it is never used", jws.RS256(k[KidAttacker], with(header(KidA), "jwk", attackerJWK), person()), verify.BadSignature),
		invalid("sig/tampered-payload", "R6", "The payload was changed after signing", parts[0]+"."+tampered+"."+parts[2], verify.BadSignature),
		invalid("sig/empty", "R6", "RS256 with an empty signature", parts[0]+"."+parts[1]+".", verify.BadSignature),
		invalid("sig/too-short", "R6", "A 10-byte signature segment", shortSig, verify.BadSignature),
		invalid("sig/too-long", "R6", "A 300-byte signature segment", longSig, verify.BadSignature),

		invalid("claims/missing-iss", "R7", "No iss", signed(with(person(), "iss", nil)), verify.MissingClaim),
		invalid("claims/missing-sub", "R7", "No sub", signed(with(person(), "sub", nil)), verify.MissingClaim),
		invalid("claims/missing-aud", "R7", "No aud", signed(with(person(), "aud", nil)), verify.MissingClaim),
		invalid("claims/missing-exp", "R7", "No exp", signed(with(person(), "exp", nil)), verify.MissingClaim),
		invalid("claims/missing-iat", "R7", "No iat", signed(with(person(), "iat", nil)), verify.MissingClaim),
		invalid("claims/missing-tid", "R7", "No tid", signed(with(person(), "tid", nil)), verify.MissingClaim),
		invalid("claims/iss-null", "R8", "iss is null", signed(with(person(), "iss", null{})), verify.InvalidClaim),
		invalid("claims/exp-string", "R8", "exp is a string", signed(with(person(), "exp", "1767226440")), verify.InvalidClaim),
		invalid("claims/sub-not-uuid", "R8", "sub is an email address", signed(with(person(), "sub", "ada@example.com")), verify.InvalidClaim),
		invalid("claims/tid-uppercase", "R8", "tid in upper case", signed(with(person(), "tid", strings.ToUpper(Tenant))), verify.InvalidClaim),
		invalid("claims/aud-empty", "R8", "aud is an empty array", signed(with(person(), "aud", []string{})), verify.InvalidClaim),
		invalid("claims/roles-string", "R8", "roles is a string", signed(with(person(), "roles", "admin")), verify.InvalidClaim),
		invalid("claims/anon-string", "R8", "anon is the string \"true\"", signed(with(person(), "anon", "true")), verify.InvalidClaim),
		invalid("claims/aud-null-element", "R8", "aud holds the audience and a null", signed(with(person(), "aud", []any{Audience, null{}})), verify.InvalidClaim),
		invalid("claims/aud-number-element", "R8", "aud holds a number beside the audience", signed(with(person(), "aud", []any{1, Audience})), verify.InvalidClaim),
		invalid("claims/roles-null-element", "R8", "roles holds a null", signed(with(person(), "roles", []any{"member", null{}})), verify.InvalidClaim),
		invalid("claims/roles-number-element", "R8", "roles holds a number", signed(with(person(), "roles", []any{1})), verify.InvalidClaim),
		invalid("claims/iat-string", "R8", "iat is a string", signed(with(person(), "iat", "1767225540")), verify.InvalidClaim),
		invalid("claims/nbf-string", "R8", "nbf is a string", signed(with(person(), "nbf", "1767225540")), verify.InvalidClaim),
		invalid("claims/exp-fractional", "R8", "exp is not an integer", signed(with(person(), "exp", float64(Now+840)+0.5)), verify.InvalidClaim),
		invalid("claims/exp-too-large", "R8", "exp beyond 2^53", signed(with(person(), "exp", int64(1)<<53+1)), verify.InvalidClaim),
		// A NumericDate is a JSON integer: a whole value written with an
		// exponent or a decimal point is not one, though it parses as a number.
		invalid("claims/exp-exponent", "R8", "exp written with an exponent (1.8e9)", signed(with(person(), "exp", number("1.8e9"))), verify.InvalidClaim),
		invalid("claims/exp-decimal-point", "R8", "exp written with a decimal point (1800000000.0)", signed(with(person(), "exp", number("1800000000.0"))), verify.InvalidClaim),
		invalid("claims/iat-exponent", "R8", "iat written with an exponent (1.76722554e9)", signed(with(person(), "iat", number("1.76722554e9"))), verify.InvalidClaim),
		invalid("claims/iat-decimal-point", "R8", "iat written with a decimal point (1767225540.0)", signed(with(person(), "iat", number("1767225540.0"))), verify.InvalidClaim),
		invalid("claims/nbf-exponent", "R8", "nbf written with an exponent (1.76722554e9)", signed(with(person(), "nbf", number("1.76722554e9"))), verify.InvalidClaim),
		invalid("claims/nbf-decimal-point", "R8", "nbf written with a decimal point (1767225540.0)", signed(with(person(), "nbf", number("1767225540.0"))), verify.InvalidClaim),
		invalid("claims/email-verified-string", "R8", "email_verified is the string \"true\"", signed(with(person(), "email_verified", "true")), verify.InvalidClaim),
		invalid("claims/token-use-null", "R8", "token_use is null", signed(with(person(), "token_use", null{})), verify.InvalidClaim),
		invalid("claims/azp-null", "R8", "azp is null", signed(with(person(), "azp", null{})), verify.InvalidClaim),
		invalid("claims/azp-array", "R8", "azp is an array", signed(with(person(), "azp", []string{"acme-web"})), verify.InvalidClaim),

		invalid("iss/other", "R9", "Another issuer", signed(with(person(), "iss", "https://attacker.example.com")), verify.WrongIssuer),
		invalid("iss/trailing-slash", "R9", "The issuer with a trailing slash", signed(with(person(), "iss", Issuer+"/")), verify.WrongIssuer),
		invalid("iss/case", "R9", "The issuer in another case", signed(with(person(), "iss", "https://Auth.example.com")), verify.WrongIssuer),
		invalid("iss/second-not-listed", "R9", "iss is the workspace's custom domain, but the backend lists no further issuer", customDomain, verify.WrongIssuer),
		func() vectors.Case {
			c := invalid("iss/not-in-list", "R9", "iss is neither the configured issuer nor the one listed in issuers", signed(with(person(), "iss", "https://attacker.example.com")), verify.WrongIssuer)
			c.Config.Issuers = []string{CustomIssuer}
			return c
		}(),

		invalid("aud/other", "R10", "Another audience", signed(with(person(), "aud", []string{"other"})), verify.WrongAudience),
		invalid("aud/client-id", "R10", "aud is a client id, as on a token meant for one client", signed(with(person(), "aud", "pact.acme-crm")), verify.WrongAudience),
		invalid("aud/agent-resource", "R10", "An AI agent's token, issued for another resource", signed(agent), verify.WrongAudience),

		invalid("time/expired-at-leeway", "R11", "exp passed 30 seconds ago: the leeway's edge", signed(with(person(), "exp", Now-30)), verify.Expired),
		invalid("time/expired", "R11", "exp passed an hour ago", signed(with(person(), "iat", Now-4500, "exp", Now-3600)), verify.Expired),
		invalid("time/nbf-ahead", "R11", "nbf is 31 seconds ahead", signed(with(person(), "nbf", Now+31)), verify.NotYetValid),
		invalid("time/iat-ahead", "R11", "iat is 31 seconds ahead", signed(with(person(), "iat", Now+31)), verify.IssuedInFuture),

		invalid("tenant/other", "R12", "A token of another workspace", signed(with(person(), "tid", OtherTenant)), verify.WrongTenant),

		invalid("system/system-token", "R13", "A system's own token", signed(system), verify.SystemToken),
		invalid("system/sys-empty", "R13", "sys present and empty", signed(with(person(), "sys", "")), verify.SystemToken),
		invalid("system/sys-null", "R13", "sys present as null: its presence is what counts", signed(with(person(), "sys", null{})), verify.SystemToken),
		invalid("system/sys-false", "R13", "sys present as false", signed(with(person(), "sys", false)), verify.SystemToken),

		invalid("client/client-token", "R13", "A client's own token where the backend expects a person", signed(client), verify.ClientToken),
		invalid("client/token-use-other", "R13", "token_use present with another value: its presence is what counts", signed(with(person(), "token_use", "person")), verify.ClientToken),
		func() vectors.Case {
			c := invalid("client/system-and-client", "R13", "sys and token_use both present, with client tokens allowed: refused as a system's", signed(with(client, "sys", "acme-crm")), verify.SystemToken)
			c.Config.AllowClientTokens = true
			return c
		}(),

		invalid("anonymous/guest", "R14", "A guest's token where the backend expects a person", signed(guest), verify.AnonymousToken),
	}
	return cases
}

// sized answers a valid token padded with an x_pad claim: the longest one
// at most verify.MaxTokenBytes long, or (over) one byte or so past it.
func sized(key *rsa.PrivateKey, over bool) string {
	pad := func(n int) map[string]any { return with(person(), "x_pad", strings.Repeat("a", n)) }
	hs := jws.Segment(header(KidA))
	sigLen := len(jws.Encode(make([]byte, key.Size())))
	length := func(n int) int { return len(hs) + 1 + len(jws.Segment(pad(n))) + 1 + sigLen }
	n := 0
	for length(n+1) <= verify.MaxTokenBytes {
		n++
	}
	if over {
		n++
	}
	return jws.RS256(key, header(KidA), pad(n))
}
