// Package client is the browser the runner pretends to be: it keeps cookies,
// sends the application's Origin on mutations, and never follows redirects.
package client

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type Response struct {
	Status     int
	Header     http.Header
	Body       []byte
	JSON       map[string]any // nil when the body is not a JSON object
	SetCookies []*http.Cookie
}

type Client struct {
	Target string // e.g. http://localhost:3999/api/auth
	Origin string // e.g. http://localhost:3999
	http   *http.Client
	jar    http.CookieJar
}

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
// carry a query string. Headers set here win over the defaults.
func (c *Client) Do(method, path string, body []byte, headers map[string]string) (*Response, error) {
	req, err := http.NewRequest(method, c.Target+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == "POST" {
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

func (c *Client) Get(path string, headers map[string]string) (*Response, error) {
	return c.Do("GET", path, nil, headers)
}

func (c *Client) PostJSON(path string, body any, headers map[string]string) (*Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return c.Do("POST", path, raw, headers)
}

// PostRaw sends bytes as they are, for a body that is not JSON.
func (c *Client) PostRaw(path string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do("POST", path, body, headers)
}
