package verify

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Identity is what a verified token says.
type Identity struct {
	Subject string
	Tenant  string
	Email   string
	// EmailVerified is the token's email_verified claim; false when absent.
	EmailVerified bool
	Roles         []string
	Anonymous     bool
	// AuthorizedParty is azp: the client a person's token was issued
	// through; empty when the token names none.
	AuthorizedParty string
	// ClientID is client_id when it is a string: on a client's own token,
	// the client's public id; on an AI agent's, the agent's.
	ClientID  string
	ExpiresAt time.Time
}

var b64 = base64.RawURLEncoding.Strict()

// Verify checks token at the instant now and answers who it belongs to, or
// an *Error that names the reason. The checks run in the order of Reasons.
func (v *Verifier) Verify(ctx context.Context, token string, now time.Time) (*Identity, error) {
	// R1 — size, before anything is decoded.
	if len(token) > MaxTokenBytes {
		return nil, refuse(TooLarge, "%d bytes, at most %d", len(token), MaxTokenBytes)
	}

	// R2 — only base64url characters and the dots: Go's base64 decoder would
	// skip a line break, and a lenient parser elsewhere must not see a
	// different token than this one signed.
	for i := 0; i < len(token); i++ {
		if !tokenByte(token[i]) {
			return nil, refuse(Malformed, "byte %d is not a base64url character or a dot", i)
		}
	}
	// Three segments; the header a JSON object with no repeated name.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, refuse(Malformed, "%d segments, want 3", len(parts))
	}
	headerRaw, errH := b64.DecodeString(parts[0])
	payloadRaw, errP := b64.DecodeString(parts[1])
	sig, errS := b64.DecodeString(parts[2])
	if errH != nil || errP != nil || errS != nil {
		return nil, refuse(Malformed, "a segment is not base64url without padding")
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerRaw, &header); err != nil || header == nil {
		return nil, refuse(Malformed, "the header is not a JSON object")
	}
	if repeatsAName(headerRaw) {
		return nil, refuse(Malformed, "the header repeats a name")
	}

	// R3 — the algorithm is fixed by the verifier, never chosen by the token.
	var alg string
	if raw, ok := header["alg"]; !ok || json.Unmarshal(raw, &alg) != nil || alg != "RS256" {
		return nil, refuse(AlgNotAllowed, "alg must be RS256")
	}

	// R4 — no critical extensions; key-carrying headers are never read; a
	// typ, when present, says this is an access token.
	if _, ok := header["crit"]; ok {
		return nil, refuse(UnsupportedHeader, "crit is not supported")
	}
	if raw, ok := header["typ"]; ok {
		var typ string
		if json.Unmarshal(raw, &typ) != nil || !(strings.EqualFold(typ, "JWT") || strings.EqualFold(typ, "at+jwt")) {
			return nil, refuse(UnsupportedHeader, "typ must be JWT or at+jwt")
		}
	}

	// R5 — the key comes from the issuer's set, by kid.
	var kid string
	if raw, ok := header["kid"]; !ok || json.Unmarshal(raw, &kid) != nil || kid == "" {
		return nil, refuse(MissingKid, "kid must be a non-empty string")
	}
	key, err := v.keys.Key(ctx, kid)
	switch {
	case errors.Is(err, ErrWeakKey):
		return nil, refuse(WeakKey, "kid %q is smaller than %d bits", kid, MinKeyBits)
	case err != nil:
		return nil, refuse(UnknownKid, "kid %q: %v", kid, err)
	}

	// R6 — the signature, over the segments exactly as received.
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) != nil {
		return nil, refuse(BadSignature, "the signature does not match kid %q", kid)
	}

	// Claims are read only now.
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payloadRaw, &claims); err != nil || claims == nil {
		return nil, refuse(Malformed, "the payload is not a JSON object")
	}
	if repeatsAName(payloadRaw) {
		return nil, refuse(Malformed, "the payload repeats a name")
	}

	// R7 — required claims.
	for _, name := range []string{"iss", "sub", "aud", "exp", "iat", "tid"} {
		if _, ok := claims[name]; !ok {
			return nil, refuse(MissingClaim, "%s is missing", name)
		}
	}

	// R8 — claim types.
	c, err := readClaims(claims)
	if err != nil {
		return nil, err
	}

	// R9 — issuer, exact: the configured one or one of the listed.
	if c.iss != v.cfg.Issuer && !slices.Contains(v.cfg.Issuers, c.iss) {
		return nil, refuse(WrongIssuer, "iss %q", c.iss)
	}

	// R10 — audience.
	if !slices.Contains(c.aud, v.cfg.Audience) {
		return nil, refuse(WrongAudience, "aud %q", c.aud)
	}

	// R11 — time, with the leeway.
	t := float64(now.UnixNano()) / 1e9
	l := v.leeway.Seconds()
	if t >= c.exp+l {
		return nil, refuse(Expired, "exp %v is past", c.exp)
	}
	if c.nbf != nil && t < *c.nbf-l {
		return nil, refuse(NotYetValid, "nbf %v is ahead", *c.nbf)
	}
	if t < c.iat-l {
		return nil, refuse(IssuedInFuture, "iat %v is ahead", c.iat)
	}

	// R12 — the configured workspace.
	if c.tid != v.cfg.Tenant {
		return nil, refuse(WrongTenant, "tid %q", c.tid)
	}

	// R13 — a system's own token never stands for a person, and a client's
	// own token only where the backend serves machines.
	if c.sys {
		return nil, refuse(SystemToken, "the token carries sys")
	}
	if c.tokenUse && !v.cfg.AllowClientTokens {
		return nil, refuse(ClientToken, "the token carries token_use")
	}

	// R14 — a guest only where the backend allows guests.
	if c.anon && !v.cfg.AllowAnonymous {
		return nil, refuse(AnonymousToken, "the token is a guest's")
	}

	// R15 — a person's token issued through another client than the one
	// this backend names. A token that names no client passes.
	if v.cfg.ClientID != "" && c.azp != "" && c.azp != v.cfg.ClientID {
		return nil, refuse(WrongClient, "azp %q", c.azp)
	}

	sec := int64(c.exp)
	return &Identity{
		Subject: c.sub, Tenant: c.tid, Email: c.email, EmailVerified: c.emailVerified, Roles: c.roles, Anonymous: c.anon,
		AuthorizedParty: c.azp, ClientID: c.clientID,
		ExpiresAt: time.Unix(sec, int64((c.exp-float64(sec))*1e9)).UTC(),
	}, nil
}

type readClaimSet struct {
	iss, sub, tid, email string
	azp, clientID        string
	aud, roles           []string
	exp, iat             float64
	nbf                  *float64
	anon, sys, tokenUse  bool
	emailVerified        bool
}

// tokenByte reports whether b may appear in a compact JWS: base64url
// characters and the dots between segments.
func tokenByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.'
}

// repeatsAName reports whether any JSON object in raw has the same name twice.
// raw is already known to be valid JSON.
func repeatsAName(raw []byte) bool {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	var walk func() bool
	walk = func() bool {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				name, _ := dec.Token()
				key, _ := name.(string)
				if seen[key] {
					return true
				}
				seen[key] = true
				if walk() {
					return true
				}
			}
			dec.Token()
		case json.Delim('['):
			for dec.More() {
				if walk() {
					return true
				}
			}
			dec.Token()
		}
		return false
	}
	return walk()
}

// maxSafeInteger is 2^53: the largest integer every JSON implementation reads
// exactly.
const maxSafeInteger = 1 << 53

// numericDate reads a NumericDate: a JSON integer within ±2^53.
func numericDate(raw json.RawMessage) (float64, bool) {
	v, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || v > maxSafeInteger || v < -maxSafeInteger {
		return 0, false
	}
	return float64(v), true
}

// stringList reads a JSON array whose every element is a string.
func stringList(raw json.RawMessage) ([]string, bool) {
	var elems []json.RawMessage
	if json.Unmarshal(raw, &elems) != nil || elems == nil {
		return nil, false
	}
	out := make([]string, len(elems))
	for i, e := range elems {
		if len(e) == 0 || e[0] != '"' || json.Unmarshal(e, &out[i]) != nil {
			return nil, false
		}
	}
	return out, true
}

// readClaims checks the type of every claim the rules name (R8). A claim the
// rules name may not be null, except roles. Claims the rules do not name are
// ignored; sys is not read at all, because its presence is what R13 refuses.
// token_use is typed (a string), but R13 refuses it by presence too.
func readClaims(m map[string]json.RawMessage) (*readClaimSet, error) {
	c := &readClaimSet{}
	bad := func(name string) error { return refuse(InvalidClaim, "%s has the wrong type or format", name) }
	// into decodes claim name into v; null and a wrong type are both false.
	into := func(name string, v any) bool {
		raw := m[name]
		return string(raw) != "null" && json.Unmarshal(raw, v) == nil
	}

	if !into("iss", &c.iss) {
		return nil, bad("iss")
	}
	if !into("sub", &c.sub) || !uuidRE.MatchString(c.sub) {
		return nil, bad("sub")
	}
	if !into("tid", &c.tid) || !uuidRE.MatchString(c.tid) {
		return nil, bad("tid")
	}
	var one string
	if into("aud", &one) {
		c.aud = []string{one}
	} else if aud, ok := stringList(m["aud"]); !ok || len(aud) == 0 {
		return nil, bad("aud")
	} else {
		c.aud = aud
	}
	var ok bool
	if c.exp, ok = numericDate(m["exp"]); !ok {
		return nil, bad("exp")
	}
	if c.iat, ok = numericDate(m["iat"]); !ok {
		return nil, bad("iat")
	}
	if raw, present := m["nbf"]; present {
		nbf, ok := numericDate(raw)
		if !ok {
			return nil, bad("nbf")
		}
		c.nbf = &nbf
	}
	if _, present := m["email"]; present && !into("email", &c.email) {
		return nil, bad("email")
	}
	if _, present := m["email_verified"]; present && !into("email_verified", &c.emailVerified) {
		return nil, bad("email_verified")
	}
	if raw, present := m["roles"]; present && string(raw) != "null" {
		if c.roles, ok = stringList(raw); !ok {
			return nil, bad("roles")
		}
	}
	if _, present := m["anon"]; present && !into("anon", &c.anon) {
		return nil, bad("anon")
	}
	var use string
	if _, c.tokenUse = m["token_use"]; c.tokenUse && !into("token_use", &use) {
		return nil, bad("token_use")
	}
	if _, present := m["azp"]; present && !into("azp", &c.azp) {
		return nil, bad("azp")
	}
	// client_id is not a rule's claim: read only when it is a string.
	if raw, present := m["client_id"]; present {
		_ = json.Unmarshal(raw, &c.clientID)
	}
	_, c.sys = m["sys"]
	return c, nil
}
