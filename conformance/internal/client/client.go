// Package client is the browser the runner pretends to be: it keeps cookies,
// sends the application's Origin on mutations, and never follows redirects.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// Response is what one request got back. Body is empty for an event stream.
type Response struct {
	Status     int
	Header     http.Header
	Body       []byte
	JSON       map[string]any // nil when the body is not a JSON object
	SetCookies []*http.Cookie
}

// Client is one browser: its own cookie jar, aimed at one backend. Besides the
// caller's headers it adds Sec-Fetch-Site: same-origin to every request and
// Origin (the application's) to every POST; a header passed to Do with the
// value "" removes the default. It is not safe to share across goroutines
// that need separate cookies; use Fresh for a new browser.
type Client struct {
	Target string // e.g. http://localhost:3999/api/auth
	Origin string // e.g. http://localhost:3999
	http   *http.Client
	jar    http.CookieJar
}

// New builds a client for target (the prefix URL) acting as a page on origin.
func New(target, origin string) *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{
		Target: strings.TrimSuffix(target, "/"),
		Origin: strings.TrimSuffix(origin, "/"),
		jar:    jar,
		http: &http.Client{
			Jar:     jar,
			Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Fresh forgets every cookie: a new browser.
func (c *Client) Fresh() *Client { return New(c.Target, c.Origin) }

// Cookies says what the jar holds for the target.
func (c *Client) Cookies() []*http.Cookie {
	u, _ := url.Parse(c.Target)
	return c.jar.Cookies(u)
}

// Do sends method path with an optional body and extra headers. A path may
// carry a query string. Headers set here win over the defaults; "" removes a
// default. The answer's JSON is filled whenever the body parses as a JSON
// object, whatever its Content-Type. SetCookies come from net/http, which
// reports a cleared cookie (Max-Age=0) as MaxAge -1. A text/event-stream answer
// is returned as soon as its headers arrive, with no Body, and the connection
// is closed. A 429 is an error ("rate limited by the backend or Cauthy: …"),
// because no check can say anything true about an answer that was throttled.
func (c *Client) Do(method, path string, body []byte, headers map[string]string) (*Response, error) {
	req, err := http.NewRequest(method, c.Target+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if method == http.MethodPost {
		req.Header.Set("Origin", c.Origin)
	}
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusTooManyRequests {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 200))
		return nil, fmt.Errorf("rate limited by the backend or Cauthy: %s %s answered 429 %s", method, path, strings.TrimSpace(string(raw)))
	}
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		return &Response{Status: res.StatusCode, Header: res.Header, SetCookies: res.Cookies()}, nil
	}
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	out := &Response{Status: res.StatusCode, Header: res.Header, Body: raw, SetCookies: res.Cookies()}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) == nil {
		out.JSON = obj
	}
	return out, nil
}

// Get sends a GET.
func (c *Client) Get(path string, headers map[string]string) (*Response, error) {
	return c.Do(http.MethodGet, path, nil, headers)
}

// PostJSON sends body encoded as JSON in a POST.
func (c *Client) PostJSON(path string, body any, headers map[string]string) (*Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return c.Do(http.MethodPost, path, raw, headers)
}

// PostRaw sends bytes as they are, for a body that is not JSON.
func (c *Client) PostRaw(path string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do(http.MethodPost, path, body, headers)
}
