// Package admin drives the part of Cauthy's admin API the dashboard-switch
// checks need, as an admin would from the dashboard: the tenant's sign-in
// settings (PUT /v1/settings/auth) and the accounts a check signed up
// (GET /v1/users, DELETE /v1/users/{id}). It remembers what it found before
// changing anything, and Restore puts it back.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client is one tenant's admin, by token. Its token is never printed.
type Client struct {
	Base   string // Cauthy's address, e.g. http://localhost:8080
	Tenant string // the workspace's slug
	token  string
	ctx    context.Context
	http   *http.Client

	mu       sync.Mutex
	original map[string]any // each changed setting as found
	made     []string       // addresses of accounts the checks signed up
}

// restoreTimeout bounds putting the tenant back: three tries of each call,
// with the waits a rate limit asks for.
const restoreTimeout = 5 * time.Minute

// New is an admin of tenant on the Cauthy at base. Every call is bound to ctx.
func New(ctx context.Context, base, tenant, token string) *Client {
	return &Client{Base: strings.TrimSuffix(base, "/"), Tenant: tenant, token: token, ctx: ctx,
		http: &http.Client{Timeout: 20 * time.Second}, original: map[string]any{}}
}

// String shows the client without its token.
func (c *Client) String() string {
	return fmt.Sprintf("admin{Base:%s Tenant:%s Token:[hidden]}", c.Base, c.Tenant)
}

// GoString keeps %#v from printing the token too.
func (c *Client) GoString() string { return c.String() }

// call sends one request and answers the decoded body. An error answer is an
// error naming the status and Cauthy's code, never a value. A 429 is tried
// again after its Retry-After, twice at most, so a run that trips Cauthy's
// rate limit still puts the tenant back.
func (c *Client) call(method, path string, body any) (map[string]any, error) {
	return c.callCtx(c.ctx, method, path, body)
}

// callCtx is call bound to ctx instead of the run's.
func (c *Client) callCtx(ctx context.Context, method, path string, body any) (map[string]any, error) {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		out, retryAfter, err := c.once(ctx, method, path, raw)
		if retryAfter < 0 || attempt == 2 {
			return out, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(retryAfter):
		}
	}
}

// once sends the request once. retryAfter is how long to wait before trying
// again when Cauthy answered 429, and -1 otherwise.
func (c *Client) once(ctx context.Context, method, path string, raw []byte) (out map[string]any, retryAfter time.Duration, err error) {
	var r io.Reader
	if raw != nil {
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, r)
	if err != nil {
		return nil, -1, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-Tenant-Key", c.Tenant)
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, -1, fmt.Errorf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, -1, fmt.Errorf("%s %s: %v", method, path, err)
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out)
	}
	if res.StatusCode >= 300 {
		code := ""
		if errs, ok := out["errors"].([]any); ok && len(errs) > 0 {
			if e, ok := errs[0].(map[string]any); ok {
				code, _ = e["code"].(string)
			}
		}
		retryAfter = -1
		if res.StatusCode == http.StatusTooManyRequests {
			retryAfter = time.Minute
			if secs, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && secs >= 0 && secs <= 120 {
				retryAfter = time.Duration(secs) * time.Second
			}
		}
		return nil, retryAfter, fmt.Errorf("%s %s answered %d %s", method, path, res.StatusCode, code)
	}
	return out, -1, nil
}

// Settings answers the tenant's sign-in settings (GET /v1/settings/auth).
func (c *Client) Settings() (map[string]any, error) {
	out, err := c.call(http.MethodGet, "/v1/settings/auth", nil)
	if err != nil {
		return nil, err
	}
	data, ok := out["data"].(map[string]any)
	if !ok {
		return nil, errors.New("GET /v1/settings/auth answered no data")
	}
	return data, nil
}

// Set changes the settings named (PUT /v1/settings/auth sends only them),
// keeping each one's value as found the first time it changes.
func (c *Client) Set(changes map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.Settings()
	if err != nil {
		return err
	}
	for k := range changes {
		if _, kept := c.original[k]; !kept {
			c.original[k] = now[k]
		}
	}
	_, err = c.call(http.MethodPut, "/v1/settings/auth", changes)
	return err
}

// Made records an account a check signed up, for Restore to delete.
func (c *Client) Made(email string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.made = append(c.made, email)
}

// Restore puts back every setting as found, and
// deletes the accounts the checks signed up. What it could not put back is
// in the errors; what it did put back is forgotten, so a second call does
// nothing more.
func (c *Client) Restore() []error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Putting the tenant back matters most when the run was stopped, so it
	// does not share the run's cancellation; it has its own time limit.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.ctx), restoreTimeout)
	defer cancel()
	var errs []error
	if len(c.original) > 0 {
		if _, err := c.callCtx(ctx, http.MethodPut, "/v1/settings/auth", c.original); err != nil {
			errs = append(errs, err)
		} else {
			c.original = map[string]any{}
		}
	}
	var left []string
	for _, email := range c.made {
		if err := c.deleteAccount(ctx, email); err != nil {
			errs = append(errs, err)
			left = append(left, email)
		}
	}
	c.made = left
	return errs
}

// deleteAccount deletes the account with exactly this address, if there is one.
func (c *Client) deleteAccount(ctx context.Context, email string) error {
	list, err := c.callCtx(ctx, http.MethodGet, "/v1/users?"+url.Values{"q": {email}}.Encode(), nil)
	if err != nil {
		return err
	}
	items, _ := list["data"].([]any)
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok || !strings.EqualFold(fmt.Sprint(m["email"]), email) {
			continue
		}
		id, _ := m["id"].(string)
		if _, err := c.callCtx(ctx, http.MethodDelete, "/v1/users/"+url.PathEscape(id), nil); err != nil {
			return err
		}
	}
	return nil
}
