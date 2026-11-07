// Package checks holds every conformance check, grouped by file.
package checks

import (
	"fmt"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
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
		res, err := c.Client.Get("/session", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if !strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
			return check.Fail(fmt.Sprintf("GET /session Cache-Control=%q, want no-store", res.Header.Get("Cache-Control")))
		}
		if !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
			return check.Fail(fmt.Sprintf("GET /session Content-Type=%q, want application/json", res.Header.Get("Content-Type")))
		}
		return check.Pass("no-store and JSON on every answer")
	}})
}
