package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
