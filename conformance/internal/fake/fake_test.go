package fake

import (
	"io"
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

func mustGet(t *testing.T, c *client.Client, path string) *client.Response {
	t.Helper()
	r, err := c.Get(path, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return r
}

func mustDo(t *testing.T, c *client.Client, method, path string, headers map[string]string) *client.Response {
	t.Helper()
	r, err := c.Do(method, path, nil, headers)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return r
}

func mustPost(t *testing.T, c *client.Client, path string, body any, headers map[string]string) *client.Response {
	t.Helper()
	r, err := c.PostJSON(path, body, headers)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return r
}

func TestTrailingSlashAndUnknownPaths(t *testing.T) {
	_, c := newClient(t, Knobs{})
	a := mustGet(t, c, "/session")
	b := mustGet(t, c, "/session/")
	if a.Status != 200 || b.Status != 200 {
		t.Fatalf("/session %d, /session/ %d", a.Status, b.Status)
	}
	for _, p := range []string{"", "/", "/nope", "/sign-in/social/"} {
		if r := mustGet(t, c, p); r.Status != 404 {
			t.Errorf("GET %q: %d, want 404", p, r.Status)
		}
	}
}

func TestPostOnlyRoutesAnswer405(t *testing.T) {
	_, c := newClient(t, Knobs{})
	for _, m := range []string{"GET", "HEAD", "PUT", "DELETE"} {
		r := mustDo(t, c, m, "/sign-out", nil)
		if r.Status != 405 || r.Header.Get("Allow") != "POST" {
			t.Errorf("%s /sign-out: %d allow=%q", m, r.Status, r.Header.Get("Allow"))
		}
	}
	_, c2 := newClient(t, Knobs{HeadNot405: true})
	if r := mustGet(t, c2, "/sign-out"); r.Status != 200 {
		t.Errorf("HeadNot405: %d", r.Status)
	}
}

func TestLogoutIsExemptFromCrossSiteAndStrict(t *testing.T) {
	_, c := newClient(t, Knobs{Strict: true})
	evil := map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}
	if r := mustDo(t, c, "POST", "/logout", evil); r.Status == 403 {
		t.Errorf("POST /logout: %d", r.Status)
	}
	if r := mustPost(t, c, "/sign-out", map[string]any{}, evil); r.Status != 403 {
		t.Errorf("cross-site /sign-out: %d", r.Status)
	}
	if r := mustPost(t, c, "/sign-out", map[string]any{}, nil); r.Status != 403 || !strings.Contains(string(r.Body), "csrf_required") {
		t.Errorf("strict without header: %d %s", r.Status, r.Body)
	}
	if r := mustPost(t, c, "/sign-out", map[string]any{}, map[string]string{"X-Cauthy-Request": "yes"}); r.Status != 403 {
		t.Errorf("strict wants the value 1: %d", r.Status)
	}
	if r := mustPost(t, c, "/sign-out", map[string]any{}, map[string]string{"X-Cauthy-Request": "1"}); r.Status != 200 {
		t.Errorf("strict with header: %d", r.Status)
	}
	if r := mustDo(t, c, "POST", "/logout", nil); r.Status == 403 {
		t.Errorf("POST /logout needs no X-Cauthy-Request: %d", r.Status)
	}
}

func TestSignInRequiresPasswordAndSignOutClears(t *testing.T) {
	s, c := newClient(t, Knobs{})
	r := mustPost(t, c, "/sign-in/email", map[string]any{"email": s.Email}, nil)
	e, _ := r.JSON["error"].(map[string]any)
	if r.Status != 400 || e["code"] != "required" || e["field"] != "password" {
		t.Fatalf("missing password: %d %s", r.Status, r.Body)
	}
	r = mustPost(t, c, "/sign-in/email", map[string]any{"email": s.Email, "password": s.Password}, nil)
	if r.Status != 200 {
		t.Fatalf("sign in: %d %s", r.Status, r.Body)
	}
	sess := mustGet(t, c, "/session")
	if sess.JSON["status"] != "authenticated" {
		t.Fatalf("session: %s", sess.Body)
	}
	old := c.Cookies()[0].Value
	if len(old) != 32 {
		t.Fatalf("session value is not 16 random bytes in hex: %q", old)
	}
	out := mustPost(t, c, "/sign-out", map[string]any{}, nil)
	var cleared bool
	for _, sc := range out.SetCookies {
		cleared = cleared || (sc.Name == "cauthy_session.0" && sc.MaxAge == -1)
	}
	if !cleared || !strings.Contains(strings.Join(out.Header.Values("Set-Cookie"), ";"), "Max-Age=0") {
		t.Fatalf("sign-out cookies: %v", out.Header.Values("Set-Cookie"))
	}
	// A replayed old cookie no longer opens a session.
	req, err := http.NewRequest("GET", s.Target()+"/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "cauthy_session.0", Value: old})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf), `"unauthenticated"`) {
		t.Fatalf("old session survived sign-out: %s", buf)
	}
}

func TestEveryTableRouteAnswersItsOwnMethod(t *testing.T) {
	s, c := newClient(t, Knobs{})
	for _, rt := range s.table.Routes {
		p := strings.ReplaceAll(rt.Path, "{provider}", "google")
		r := mustDo(t, c, rt.Method, p, nil)
		if r.Status == 404 || r.Status == 405 {
			t.Errorf("%s %s: %d", rt.Method, p, r.Status)
		}
	}
}
