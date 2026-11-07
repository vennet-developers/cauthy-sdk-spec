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
	"strings"
	"time"
)

// Identity is what a verified token says.
type Identity struct {
	Subject   string
	Tenant    string
	Email     string
	Roles     []string
	Anonymous bool
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

	// R2 — three base64url segments; the header a JSON object.
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

	// R3 — the algorithm is fixed by the verifier, never chosen by the token.
	var alg string
	if raw, ok := header["alg"]; !ok || json.Unmarshal(raw, &alg) != nil || alg != "RS256" {
		return nil, refuse(AlgNotAllowed, "alg must be RS256")
	}

	// R4 — no critical extensions; key-carrying headers are never read.
	if _, ok := header["crit"]; ok {
		return nil, refuse(UnsupportedHeader, "crit is not supported")
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
	l := v.cfg.Leeway.Seconds()
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

	// R13 — a system's own token never stands for a person.
	if c.sys {
		return nil, refuse(SystemToken, "the token carries sys")
	}

	// R14 — a guest only where the backend allows guests.
	if c.anon && !v.cfg.AllowAnonymous {
		return nil, refuse(AnonymousToken, "the token is a guest's")
	}

	sec := int64(c.exp)
	return &Identity{
		Subject: c.sub, Tenant: c.tid, Email: c.email, Roles: c.roles, Anonymous: c.anon,
		ExpiresAt: time.Unix(sec, int64((c.exp-float64(sec))*1e9)).UTC(),
	}, nil
}

type readClaimSet struct {
	iss, sub, tid, email string
	aud, roles           []string
	exp, iat             float64
	nbf                  *float64
	anon, sys            bool
}

// readClaims checks the type of every claim the rules name (R8). A claim the
// rules name may not be null, except roles. Claims the rules do not name are
// ignored.
func readClaims(m map[string]json.RawMessage) (*readClaimSet, error) {
	c := &readClaimSet{}
	bad := func(name string) error { return refuse(InvalidClaim, "%s has the wrong type or format", name) }
	// into decodes claim name into v; null and a wrong type are both false.
	into := func(name string, v any) bool {
		raw := m[name]
		return string(raw) != "null" && json.Unmarshal(raw, v) == nil
	}
	// num decodes a JSON number. json.Number would also take "123" quoted,
	// which a NumericDate is not.
	num := func(name string, f *float64) bool {
		var n json.Number
		if strings.HasPrefix(string(m[name]), `"`) || !into(name, &n) {
			return false
		}
		v, err := n.Float64()
		*f = v
		return err == nil
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
	} else if !into("aud", &c.aud) || len(c.aud) == 0 {
		return nil, bad("aud")
	}
	if !num("exp", &c.exp) {
		return nil, bad("exp")
	}
	if !num("iat", &c.iat) {
		return nil, bad("iat")
	}
	if _, ok := m["nbf"]; ok {
		var nbf float64
		if !num("nbf", &nbf) {
			return nil, bad("nbf")
		}
		c.nbf = &nbf
	}
	if _, ok := m["email"]; ok && !into("email", &c.email) {
		return nil, bad("email")
	}
	if raw, ok := m["roles"]; ok && string(raw) != "null" && !into("roles", &c.roles) {
		return nil, bad("roles")
	}
	if _, ok := m["anon"]; ok && !into("anon", &c.anon) {
		return nil, bad("anon")
	}
	if _, ok := m["sys"]; ok {
		var s string
		if !into("sys", &s) {
			return nil, bad("sys")
		}
		c.sys = true
	}
	return c, nil
}
