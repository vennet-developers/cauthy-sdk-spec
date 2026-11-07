package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestKeepsCookiesAndSendsOrigin(t *testing.T) {
	var gotCookie, gotOrigin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/sign-in/email":
			gotOrigin = r.Header.Get("Origin")
			http.SetCookie(w, &http.Cookie{Name: "cauthy_session.0", Value: "abc", Path: "/", HttpOnly: true})
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"signed_in"}`))
		case "/api/auth/session":
			if c, err := r.Cookie("cauthy_session.0"); err == nil {
				gotCookie = c.Value
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"session":null,"status":"unauthenticated"}`))
		}
	}))
	defer srv.Close()

	c := New(srv.URL+"/api/auth", srv.URL)
	res, err := c.PostJSON("/sign-in/email", map[string]any{"email": "a@example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || res.JSON["status"] != "signed_in" {
		t.Fatalf("post: %+v", res)
	}
	if gotOrigin != srv.URL {
		t.Fatalf("origin: %q", gotOrigin)
	}
	if len(res.SetCookies) != 1 || res.SetCookies[0].Name != "cauthy_session.0" || !res.SetCookies[0].HttpOnly {
		t.Fatalf("set-cookie: %+v", res.SetCookies)
	}
	if _, err := c.Get("/session", nil); err != nil {
		t.Fatal(err)
	}
	if gotCookie != "abc" {
		t.Fatalf("cookie not sent back: %q", gotCookie)
	}
}

func TestRawRequestDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://id.example/authorize", http.StatusFound)
	}))
	defer srv.Close()
	c := New(srv.URL+"/api/auth", srv.URL)
	res, err := c.Do("GET", "/login", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 302 || res.Header.Get("Location") != "https://id.example/authorize" {
		t.Fatalf("redirect: %d %q", res.Status, res.Header.Get("Location"))
	}
}

func TestFreshClientsShareNoCookies(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("k"); err == nil {
			seen = c.Value
		} else {
			seen = ""
		}
		http.SetCookie(w, &http.Cookie{Name: "k", Value: "v", Path: "/"})
	}))
	defer srv.Close()
	a := New(srv.URL+"/api/auth", srv.URL)
	a.Get("/x", nil)
	a.Get("/x", nil)
	if seen != "v" {
		t.Fatalf("first client lost its cookie: %q", seen)
	}
	b := a.Fresh()
	b.Get("/x", nil)
	if seen != "" || len(b.Cookies()) != 1 {
		t.Fatalf("fresh client inherited cookies: %q", seen)
	}
}

func TestHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer srv.Close()
	c := New(srv.URL+"/api/auth", srv.URL)
	c.Get("/x", nil)
	if got.Get("Origin") != "" {
		t.Fatalf("GET carries Origin %q", got.Get("Origin"))
	}
	if got.Get("Sec-Fetch-Site") != "same-origin" {
		t.Fatalf("Sec-Fetch-Site: %q", got.Get("Sec-Fetch-Site"))
	}
	c.PostJSON("/x", map[string]any{}, map[string]string{"Origin": ""})
	if _, ok := got["Origin"]; ok {
		t.Fatalf("Origin not removed: %q", got.Get("Origin"))
	}
	c.PostJSON("/x", map[string]any{}, map[string]string{"Sec-Fetch-Site": ""})
	if _, ok := got["Sec-Fetch-Site"]; ok {
		t.Fatal("Sec-Fetch-Site not removed")
	}
	c.PostJSON("/x", map[string]any{}, map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
	if got.Get("Origin") != "https://evil.example" || got.Get("Sec-Fetch-Site") != "cross-site" {
		t.Fatalf("overrides lost: %v", got)
	}
}

func TestJSONIsNilForNonObjects(t *testing.T) {
	for _, body := range []string{`[]`, `null`, `text`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		res, err := New(srv.URL, srv.URL).Get("/", nil)
		srv.Close()
		if err != nil || res.JSON != nil {
			t.Errorf("%s: JSON=%v err=%v", body, res.JSON, err)
		}
	}
}

func TestClearedCookieIsMaxAgeMinusOneAndGoneFromJar(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/clear" {
			w.Header().Add("Set-Cookie", "x=; Path=/; Max-Age=0")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "x", Value: "1", Path: "/"})
	}))
	defer srv.Close()
	c := New(srv.URL, srv.URL)
	c.Get("/set", nil)
	if len(c.Cookies()) != 1 {
		t.Fatal("cookie not stored")
	}
	res, _ := c.Get("/clear", nil)
	if len(res.SetCookies) != 1 || res.SetCookies[0].MaxAge != -1 {
		t.Fatalf("set-cookie: %+v", res.SetCookies)
	}
	if len(c.Cookies()) != 0 {
		t.Fatal("cleared cookie still in the jar")
	}
}

func TestEventStreamBodyIsNotRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done() // never ends on its own
	}))
	defer srv.Close()
	done := make(chan *Response, 1)
	go func() {
		res, _ := New(srv.URL, srv.URL).Get("/events", nil)
		done <- res
	}()
	select {
	case res := <-done:
		if res == nil || res.Status != 200 || res.Header.Get("Content-Type") != "text/event-stream" || len(res.Body) != 0 {
			t.Fatalf("stream: %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client waited for a stream to end")
	}
}
