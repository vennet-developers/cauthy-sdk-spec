package fake

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/cauthykey"
)

// keyring is what the fake Cauthy knows of keys: the public key per kid, the
// client it belongs to, the jtis seen and the tokens it issued.
type keyring struct {
	mu     sync.Mutex
	pub    map[string]ed25519.PublicKey // kid -> key
	client map[string]string            // kid -> client id
	jtis   map[string]bool
	tokens map[string]string // access token -> kid
}

func (s *Server) ring() *keyring {
	s.keysOnce.Do(func() {
		s.keys = &keyring{pub: map[string]ed25519.PublicKey{}, client: map[string]string{}, jtis: map[string]bool{}, tokens: map[string]string{}}
	})
	return s.keys
}

// IssueKey makes a CAUTHY_KEY for the fake's client (ClientID) with issuer
// base, as the dashboard would: a random secret, the public key registered.
func (s *Server) IssueKey(base string) string {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	key, err := cauthykey.Compose(base, ClientID, base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		panic(err)
	}
	k, _ := cauthykey.Parse(key)
	d := k.Derive()
	r := s.ring()
	r.mu.Lock()
	r.pub[d.KID], r.client[d.KID] = d.Public, ClientID
	r.mu.Unlock()
	return key
}

// assertionToken answers client_credentials with an EdDSA assertion.
func (s *Server) assertionToken(w http.ResponseWriter, r *http.Request, base string) {
	_ = r.ParseForm()
	a := r.PostForm.Get("client_assertion")
	parts := strings.Split(a, ".")
	kid := headerKid(parts)
	rg := s.ring()
	rg.mu.Lock()
	defer rg.mu.Unlock()
	pub, ok := rg.pub[kid]
	if !ok {
		oauthErr(w, 401, "invalid_client")
		return
	}
	c, err := cauthykey.VerifyAssertion(pub, a)
	now := time.Now().Unix()
	if err != nil || c.Iss != rg.client[kid] || c.Sub != c.Iss || c.Aud != base+"/v1/oauth/token" ||
		c.Exp < now-30 || c.Exp > now+330 || c.Jti == "" || rg.jtis[c.Jti] {
		oauthErr(w, 401, "invalid_client")
		return
	}
	rg.jtis[c.Jti] = true
	tok := newSessionValue()
	rg.tokens[tok] = kid
	writeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 600})
}

// self answers GET /v1/connect/self.
func (s *Server) self(w http.ResponseWriter, r *http.Request, base string) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	rg := s.ring()
	rg.mu.Lock()
	kid, ok := rg.tokens[tok]
	rg.mu.Unlock()
	if !ok {
		writeJSON(w, 401, map[string]any{"code": "invalid_token", "message": "no valid system token"})
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"issuer": base, "audience": base, "tenant": map[string]any{"id": "00000000-0000-4000-8000-0000000000a1", "slug": Tenant},
		"system": "acme-crm", "client_id": ClientID, "sign_in_client_id": ClientID,
		"app_urls": []string{s.origin()}, "callback_path": "/api/auth/callback",
		"key": map[string]any{"kid": kid, "retires_at": nil},
	}})
}

// headerKid reads the kid of a compact JWS's header ("" when there is none).
func headerKid(parts []string) string {
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h.Kid
}

// oauthErr answers an OAuth error ({"error": code}), as Cauthy's token endpoint.
func oauthErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
