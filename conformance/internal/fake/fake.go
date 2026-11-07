// Package fake is a small auth-bff backend for the runner's own tests. It is
// right by default, and each knob makes it wrong in one way.
//
// Routes the fake does not model answer from protocol/routes.yaml: a POST
// route gets 400 bad_request, a GET route 401 unauthenticated, and any other
// method on a POST-only route 405 with Allow: POST. Only paths outside the
// table answer 404. Unmodeled GETs answer 401 even on routes that need no
// session (such as /look): a check that needs another answer from
// such a route must model the route here first.
package fake

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

type Knobs struct {
	NoHttpOnly            bool // session cookie without HttpOnly
	NoSameSite            bool
	NoCacheControl        bool
	AcceptCrossSite       bool // skips the Origin check
	NoTrailingSlash       bool // /session/ answers 404
	HeadNot405            bool // GET on a POST route answers 200 instead of 405
	ErrorFlat             bool // errors as {"code":...} instead of {"error":{...}}
	NoAuth401             bool // /me without a session answers 200
	Strict                bool // Cauthy-Protocol header, X-Cauthy-Request required, next field
	PersistentAllowed     bool // methods.persistentSessions and Max-Age on remember
	RememberIgnoresTenant bool // sets Max-Age on remember even when the tenant does not allow it
	SignInBroken          bool // every sign-in answers 401 invalid_credentials
	MFARequired           bool // a correct sign-in answers mfa_required, with no session
	RateLimited           bool // every sign-in answers 429
	UnknownNot404         bool // a path outside the table answers 200 JSON
	NoHead                bool // HEAD answers 405
	LenientJSON           bool // a non-JSON sign-in body is treated as {}
	CookiePathWrong       bool // the session cookie has Path=/api
	NoSecure              bool // no Secure on the session cookie even when the application origin is https
	JSONAsTextPlain       bool // JSON answers carry content-type text/plain
	NoErrorField          bool // errors never carry "field"
	NoProtocolOn404       bool // the plain-text 404 lacks Cauthy-Protocol
	LogoutNotExempt       bool // POST /logout needs X-Cauthy-Request at strict
	LogoutMissing         bool // /logout is not served: 404
}

type Server struct {
	*httptest.Server
	Knobs     Knobs
	Email     string
	Password  string
	appOrigin string // guarded by mu

	mu       sync.Mutex
	signIns  int             // sessions opened so far
	signedIn map[string]bool // cookie value → signed in
	table    *routes.Table
}

var (
	tableOnce sync.Once
	table     *routes.Table
)

// loadTable reads protocol/routes.yaml once, relative to this source file.
func loadTable() *routes.Table {
	tableOnce.Do(func() {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			panic("fake: cannot locate its own source file to find protocol/routes.yaml")
		}
		path := filepath.Join(filepath.Dir(file), "..", "..", "..", "protocol", "routes.yaml")
		t, err := routes.Load(path)
		if err != nil {
			panic(fmt.Sprintf("fake: cannot load the route table from %s: %v", path, err))
		}
		table = t
	})
	return table
}

func newSessionValue() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

const prefix = "/api/auth"

func New(k Knobs) *Server {
	s := &Server{Knobs: k, Email: "ana@example.com", Password: "correct horse battery staple", signedIn: map[string]bool{}, table: loadTable()}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	s.appOrigin = s.URL
	return s
}

// SignIns says how many sessions the server has opened; OpenSessions how many are still open.
func (s *Server) SignIns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signIns
}

func (s *Server) OpenSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.signedIn)
}

// SetAppOrigin changes the origin of the application the fake trusts (default:
// its own URL). With an https origin the session cookie is Secure.
func (s *Server) SetAppOrigin(o string) {
	s.mu.Lock()
	s.appOrigin = o
	s.mu.Unlock()
}

func (s *Server) origin() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appOrigin
}

func (s *Server) Target() string { return s.URL + prefix }

func (s *Server) headers(w http.ResponseWriter) {
	if s.Knobs.Strict {
		w.Header().Set("Cauthy-Protocol", "1")
	}
	if !s.Knobs.NoCacheControl {
		w.Header().Set("Cache-Control", "no-store")
	}
}

func (s *Server) write(w http.ResponseWriter, status int, body any) {
	s.headers(w)
	if s.Knobs.JSONAsTextPlain {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// text answers the plain-text 404 and 405 of the protocol.
func (s *Server) text(w http.ResponseWriter, status int, msg string) {
	s.headers(w)
	if s.Knobs.NoProtocolOn404 && status == 404 {
		w.Header().Del("Cauthy-Protocol")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(msg))
}

func (s *Server) problem(w http.ResponseWriter, status int, code, message, field string) {
	e := map[string]any{"code": code, "message": message}
	if field != "" && !s.Knobs.NoErrorField {
		e["field"] = field
	}
	if s.Knobs.ErrorFlat {
		s.write(w, status, e)
		return
	}
	s.write(w, status, map[string]any{"error": e})
}

func (s *Server) setSession(w http.ResponseWriter, value string, persistent bool) {
	c := &http.Cookie{Name: "cauthy_session.0", Value: value, Path: "/", HttpOnly: !s.Knobs.NoHttpOnly,
		Secure: strings.HasPrefix(s.origin(), "https://") && !s.Knobs.NoSecure}
	if s.Knobs.CookiePathWrong {
		c.Path = "/api"
	}
	if !s.Knobs.NoSameSite {
		c.SameSite = http.SameSiteLaxMode
	}
	if persistent {
		c.MaxAge = 2592000
	}
	s.mu.Lock()
	s.signedIn[value] = true
	s.signIns++
	s.mu.Unlock()
	http.SetCookie(w, c)
}

func (s *Server) clearSession(w http.ResponseWriter) {
	// Max-Age=0 is what the protocol says; net/http spells it as -1.
	http.SetCookie(w, &http.Cookie{Name: "cauthy_session.0", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (s *Server) sessionFor(value string) map[string]any {
	s.mu.Lock()
	ok := s.signedIn[value]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	return map[string]any{
		"user":          map[string]any{"id": "u1", "email": s.Email, "name": "Ana", "emailVerified": true, "restricted": false},
		"tenantId":      "t1",
		"roles":         []string{"member"},
		"organizations": []any{},
		"expiresAt":     "2030-01-01T00:00:00Z",
	}
}

func (s *Server) session(r *http.Request) map[string]any {
	c, err := r.Cookie("cauthy_session.0")
	if err != nil {
		return nil
	}
	return s.sessionFor(c.Value)
}

func (s *Server) crossSite(r *http.Request) bool {
	if s.Knobs.AcceptCrossSite {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		return origin != s.origin()
	}
	site := r.Header.Get("Sec-Fetch-Site")
	return site != "" && site != "same-origin"
}

// methodsFor maps each method the table gives a path to its route (segments
// of the form {x} match any one non-empty segment); nil when the path is not in the table.
func (s *Server) methodsFor(path string) map[string]*routes.Route {
	var out map[string]*routes.Route
	have := strings.Split(path, "/")
	for _, rt := range s.table.Routes {
		want := strings.Split(rt.Path, "/")
		if len(want) != len(have) {
			continue
		}
		match := true
		for i := range want {
			if strings.HasPrefix(want[i], "{") {
				if have[i] == "" {
					match = false
				}
				continue
			}
			if want[i] != have[i] {
				match = false
			}
		}
		if match {
			if out == nil {
				out = map[string]*routes.Route{}
			}
			out[rt.Method] = rt
		}
	}
	return out
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, prefix) {
		s.text(w, 404, "Not found")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if !s.Knobs.NoTrailingSlash {
		path = strings.TrimRight(path, "/")
	}
	if path == "" {
		path = "/"
	}
	method := r.Method
	if method == http.MethodHead && s.Knobs.NoHead {
		s.text(w, 405, "Method not allowed")
		return
	}
	if method == http.MethodHead {
		method = http.MethodGet
	}
	methods := s.methodsFor(path)
	if s.Knobs.LogoutMissing && path == "/logout" {
		methods = nil
	}
	if methods == nil {
		if s.Knobs.UnknownNot404 {
			s.write(w, 200, map[string]any{"status": "ok"})
			return
		}
		s.text(w, 404, "Not found")
		return
	}
	if methods[method] == nil {
		if methods[http.MethodPost] != nil && len(methods) == 1 {
			// A POST-only route: any other method is 405 with Allow: POST.
			if s.Knobs.HeadNot405 && method == http.MethodGet {
				s.write(w, 200, map[string]any{"status": "ok"})
				return
			}
			w.Header().Set("Allow", "POST")
		}
		s.text(w, 405, "Method not allowed")
		return
	}
	route := methods[method]
	if method == http.MethodPost {
		if route.Needs("crosssite") && s.crossSite(r) {
			s.problem(w, 403, "cross_site", "Cross-site request", "")
			return
		}
		// POST /logout is exempt: a plain HTML form signs out and cannot add headers.
		if s.Knobs.Strict && (route.ID != "hosted.logout_post" || s.Knobs.LogoutNotExempt) && r.Header.Get("X-Cauthy-Request") != "1" {
			s.problem(w, 403, "csrf_required", "X-Cauthy-Request: 1 is required", "")
			return
		}
	}
	switch method + " " + path {
	case "GET /session":
		if sess := s.session(r); sess != nil {
			s.write(w, 200, map[string]any{"session": sess, "status": "authenticated"})
		} else {
			s.write(w, 200, map[string]any{"session": nil, "status": "unauthenticated"})
		}
	case "GET /login":
		// The hosted sign-in: a redirect to Cauthy.
		s.headers(w)
		w.Header().Set("Location", "https://auth.example/authorize")
		w.WriteHeader(302)
	case "GET /methods":
		m := map[string]any{"providers": []any{}, "passwordSignIn": true, "signUp": true, "magicLink": false,
			"passkey": false, "passkeyHere": false, "passkeyOnCauthy": false, "sso": false}
		if s.Knobs.PersistentAllowed {
			m["persistentSessions"] = true
		}
		s.write(w, 200, m)
	case "POST /sign-in/email":
		if s.Knobs.RateLimited {
			s.problem(w, 429, "rate_limited", "Too many attempts", "")
			return
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || body == nil {
			if s.Knobs.LenientJSON {
				body = map[string]any{}
			}
		}
		if body == nil {
			s.problem(w, 400, "bad_request", "A JSON object is required", "")
			return
		}
		email, _ := body["email"].(string)
		password, _ := body["password"].(string)
		if email == "" {
			s.problem(w, 400, "required", "The email is required", "email")
			return
		}
		if !strings.Contains(email, "@") {
			s.problem(w, 400, "invalid_email", "That is not an email", "email")
			return
		}
		if password == "" {
			s.problem(w, 400, "required", "The password is required", "password")
			return
		}
		if s.Knobs.SignInBroken || email != s.Email || password != s.Password {
			s.problem(w, 401, "invalid_credentials", "Wrong email or password", "")
			return
		}
		if s.Knobs.MFARequired {
			s.write(w, 200, map[string]any{"status": "mfa_required"})
			return
		}
		remember, _ := body["remember"].(bool)
		persistent := remember && (s.Knobs.PersistentAllowed || s.Knobs.RememberIgnoresTenant)
		value := newSessionValue()
		s.setSession(w, value, persistent)
		out := map[string]any{"status": "signed_in", "session": s.sessionFor(value)}
		if s.Knobs.Strict {
			out["next"] = "done"
		}
		s.write(w, 200, out)
	case "POST /sign-out":
		if c, err := r.Cookie("cauthy_session.0"); err == nil {
			s.mu.Lock()
			delete(s.signedIn, c.Value)
			s.mu.Unlock()
		}
		s.clearSession(w)
		s.write(w, 200, map[string]any{"status": "signed_out"})
	case "GET /me":
		if s.session(r) == nil && !s.Knobs.NoAuth401 {
			s.problem(w, 401, "unauthenticated", "Sign in first", "")
			return
		}
		s.write(w, 200, map[string]any{"account": map[string]any{"id": "u1", "email": s.Email, "name": "Ana", "emailVerified": true, "hasPassword": true, "mfaEnabled": false}})
	case "GET /me/organizations":
		if s.session(r) == nil {
			s.problem(w, 401, "unauthenticated", "Sign in first", "")
			return
		}
		s.write(w, 200, map[string]any{"organizations": []any{}})
	default:
		// Any other route of the table: a shape error or a missing session,
		// never 404 or 405.
		if method == http.MethodPost {
			s.problem(w, 400, "bad_request", "Not exercised by the fake", "")
			return
		}
		s.problem(w, 401, "unauthenticated", "Not exercised by the fake", "")
	}
}
