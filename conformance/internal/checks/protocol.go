// Package checks holds every conformance check, grouped by file.
package checks

import (
	"fmt"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
)

// RegisterAll adds every group to the registry, in report order.
func RegisterAll(reg *check.Registry) {
	RegisterProtocol(reg)
	RegisterSession(reg)
	RegisterErrors(reg)
	RegisterCSRF(reg)
	RegisterTable(reg)
	RegisterStrict(reg)
}

func RegisterProtocol(reg *check.Registry) {
	reg.Add(check.Check{ID: "protocol.unknown_is_404", Group: "protocol", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Get("/nope-does-not-exist", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if res.Status != 404 {
			return check.Fail(fmt.Sprintf("GET /nope-does-not-exist answered %d, want 404", res.Status))
		}
		return check.Pass("404 on an unknown route")
	}})
	reg.Add(check.Check{ID: "protocol.trailing_slash", Group: "protocol", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Get("/session/", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if res.Status != 200 || res.JSON == nil || res.JSON["status"] == nil {
			return check.Fail(fmt.Sprintf("GET /session/ answered %d; a trailing slash must be ignored", res.Status))
		}
		return check.Pass("/session/ is /session")
	}})
	reg.Add(check.Check{ID: "protocol.head_as_get", Group: "protocol", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Do("HEAD", "/session", nil, nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if res.Status != 200 {
			return check.Fail(fmt.Sprintf("HEAD /session answered %d, want 200", res.Status))
		}
		return check.Pass("HEAD behaves as GET")
	}})
	reg.Add(check.Check{ID: "protocol.get_on_post_is_405", Group: "protocol", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Get("/sign-in/email", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if res.Status != 405 || !strings.Contains(res.Header.Get("Allow"), "POST") {
			return check.Fail(fmt.Sprintf("GET /sign-in/email answered %d with Allow=%q, want 405 and Allow: POST", res.Status, res.Header.Get("Allow")))
		}
		return check.Pass("405 with Allow: POST on a POST-only route")
	}})
	reg.Add(check.Check{ID: "protocol.no_store", Group: "protocol", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		answers, err := sampleAnswers(c)
		if err != nil {
			return check.Fail(err.Error())
		}
		for _, a := range answers {
			if !strings.Contains(a.res.Header.Get("Cache-Control"), "no-store") {
				return check.Fail(fmt.Sprintf("%s: Cache-Control=%q, want no-store", a.label, a.res.Header.Get("Cache-Control")))
			}
			// Only an answer with a JSON body must say so; the plain-text 404 and 405 and a redirect need not.
			if a.res.JSON != nil && !strings.HasPrefix(a.res.Header.Get("Content-Type"), "application/json") {
				return check.Fail(fmt.Sprintf("%s: Content-Type=%q on a JSON answer, want application/json", a.label, a.res.Header.Get("Content-Type")))
			}
		}
		return check.Pass(fmt.Sprintf("no-store on %d kinds of answer, JSON where the body is JSON", len(answers)))
	}})
}

type answer struct {
	label string
	res   *client.Response
}

// sampleAnswers gets one answer of each kind a backend gives: a JSON read, the
// methods, an error from a POST, the plain-text 404 and 405, and the hosted
// redirect. The push event stream is left out on purpose: it is text/event-stream.
func sampleAnswers(c *check.Ctx) ([]answer, error) {
	hdr := map[string]string{"X-Cauthy-Request": "1"}
	var out []answer
	add := func(label string, res *client.Response, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		out = append(out, answer{label, res})
		return nil
	}
	b := c.Client.Fresh()
	res, err := b.Get("/session", nil)
	if err := add("GET /session", res, err); err != nil {
		return nil, err
	}
	res, err = b.Get("/methods", nil)
	if err := add("GET /methods", res, err); err != nil {
		return nil, err
	}
	res, err = b.PostJSON("/sign-in/email", map[string]any{}, hdr)
	if err := add("POST /sign-in/email with an invalid body", res, err); err != nil {
		return nil, err
	}
	res, err = b.Get("/nope-does-not-exist", nil)
	if err := add("GET /nope-does-not-exist (404)", res, err); err != nil {
		return nil, err
	}
	res, err = b.Get("/sign-in/email", nil)
	if err := add("GET /sign-in/email (405)", res, err); err != nil {
		return nil, err
	}
	res, err = b.Get("/login", nil)
	if err := add("GET /login (redirect)", res, err); err != nil {
		return nil, err
	}
	return out, nil
}
