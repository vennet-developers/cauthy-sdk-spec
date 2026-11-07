package fake

import (
	"net/http"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
)

func newClient(t *testing.T, k Knobs) (*Server, *client.Client) {
	s := New(k)
	t.Cleanup(s.Close)
	return s, client.New(s.Target(), s.URL)
}

func TestTrailingSlashAndUnknownPaths(t *testing.T) {
	_, c := newClient(t, Knobs{})
	a, _ := c.Get("/session", nil)
	b, _ := c.Get("/session/", nil)
	if a.Status != 200 || b.Status != 200 {
		t.Fatalf("/session %d, /session/ %d", a.Status, b.Status)
	}
	for _, p := range []string{"", "/", "/nope", "/sign-in/social/"} {
		if r, _ := c.Get(p, nil); r.Status != 404 {
			t.Errorf("GET %q: %d, want 404", p, r.Status)
		}
	}
}

func TestPostOnlyRoutesAnswer405(t *testing.T) {
	_, c := newClient(t, Knobs{})
	for _, m := range []string{"GET", "HEAD", "PUT", "DELETE"} {
		r, _ := c.Do(m, "/sign-out", nil, nil)
		if r.Status != 405 || r.Header.Get("Allow") != "POST" {
			t.Errorf("%s /sign-out: %d allow=%q", m, r.Status, r.Header.Get("Allow"))
		}
	}
	s, c2 := newClient(t, Knobs{HeadNot405: true})
	_ = s
	if r, _ := c2.Get("/sign-out", nil); r.Status != 200 {
		t.Errorf("HeadNot405: %d", r.Status)
	}
}

func TestLogoutIsExemptFromCrossSiteAndStrict(t *testing.T) {
	_, c := newClient(t, Knobs{Strict: true})
	evil := map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}
	if r, _ := c.Do("POST", "/logout", nil, evil); r.Status == 403 {
		t.Errorf("POST /logout: %d", r.Status)
	}
	if r, _ := c.PostJSON("/sign-out", map[string]any{}, evil); r.Status != 403 {
		t.Errorf("cross-site /sign-out: %d", r.Status)
	}
	if r, _ := c.PostJSON("/sign-out", map[string]any{}, nil); r.Status != 403 || !strings.Contains(string(r.Body), "csrf_required") {
		t.Errorf("strict without header: %d %s", r.Status, r.Body)
	}
	if r, _ := c.PostJSON("/sign-out", map[string]any{}, map[string]string{"X-Cauthy-Request": "yes"}); r.Status != 403 {
		t.Errorf("strict wants the value 1: %d", r.Status)
	}
	if r, _ := c.PostJSON("/sign-out", map[string]any{}, map[string]string{"X-Cauthy-Request": "1"}); r.Status != 200 {
		t.Errorf("strict with header: %d", r.Status)
	}
	if r, _ := c.Do("POST", "/logout", nil, nil); r.Status == 403 {
		t.Errorf("POST /logout needs no X-Cauthy-Request: %d", r.Status)
	}
}

func TestSignInRequiresPasswordAndSignOutClears(t *testing.T) {
	s, c := newClient(t, Knobs{})
	r, _ := c.PostJSON("/sign-in/email", map[string]any{"email": s.Email}, nil)
	e, _ := r.JSON["error"].(map[string]any)
	if r.Status != 400 || e["code"] != "required" || e["field"] != "password" {
		t.Fatalf("missing password: %d %s", r.Status, r.Body)
	}
	r, _ = c.PostJSON("/sign-in/email", map[string]any{"email": s.Email, "password": s.Password}, nil)
	if r.Status != 200 {
		t.Fatalf("sign in: %d %s", r.Status, r.Body)
	}
	sess, _ := c.Get("/session", nil)
	if sess.JSON["status"] != "authenticated" {
		t.Fatalf("session: %s", sess.Body)
	}
	old := c.Cookies()[0].Value
	if len(old) != 32 {
		t.Fatalf("session value is not 16 random bytes in hex: %q", old)
	}
	out, _ := c.PostJSON("/sign-out", map[string]any{}, nil)
	var cleared bool
	for _, sc := range out.SetCookies {
		cleared = cleared || (sc.Name == "cauthy_session.0" && sc.MaxAge == -1)
	}
	if !cleared || !strings.Contains(strings.Join(out.Header.Values("Set-Cookie"), ";"), "Max-Age=0") {
		t.Fatalf("sign-out cookies: %v", out.Header.Values("Set-Cookie"))
	}
	// A replayed old cookie no longer opens a session.
	req, _ := http.NewRequest("GET", s.Target()+"/session", nil)
	req.AddCookie(&http.Cookie{Name: "cauthy_session.0", Value: old})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := make([]byte, 200)
	n, _ := res.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), `"unauthenticated"`) {
		t.Fatalf("old session survived sign-out: %s", buf[:n])
	}
}

func TestEveryTableRouteAnswersItsOwnMethod(t *testing.T) {
	s, c := newClient(t, Knobs{})
	for _, rt := range s.table.Routes {
		p := strings.ReplaceAll(rt.Path, "{provider}", "google")
		r, _ := c.Do(rt.Method, p, nil, nil)
		if r.Status == 404 || r.Status == 405 {
			t.Errorf("%s %s: %d", rt.Method, p, r.Status)
		}
	}
}
