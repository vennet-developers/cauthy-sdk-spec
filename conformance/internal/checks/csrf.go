package checks

import (
	"fmt"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
)

func RegisterCSRF(reg *check.Registry) {
	reg.Add(check.Check{ID: "csrf.foreign_origin_403", Group: "csrf", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Fresh().PostJSON("/sign-in/email", map[string]any{"email": "a@example.com", "password": "x"},
			map[string]string{"Origin": "https://evil.example", "X-Cauthy-Request": "1"})
		if err != nil {
			return check.Fail(err.Error())
		}
		e, why := errorOf(res)
		if res.Status != 403 || why != "" || e["code"] != "cross_site" {
			return check.Fail(fmt.Sprintf("foreign Origin: %d %s, want 403 cross_site", res.Status, res.Body))
		}
		return check.Pass("403 cross_site on a foreign Origin")
	}})
	reg.Add(check.Check{ID: "csrf.fetch_site_cross_403", Group: "csrf", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Fresh().PostJSON("/sign-in/email", map[string]any{"email": "a@example.com", "password": "x"},
			map[string]string{"Origin": "", "Sec-Fetch-Site": "cross-site", "X-Cauthy-Request": "1"})
		if err != nil {
			return check.Fail(err.Error())
		}
		e, why := errorOf(res)
		if res.Status != 403 || why != "" || e["code"] != "cross_site" {
			return check.Fail(fmt.Sprintf("Sec-Fetch-Site: cross-site without Origin: %d %s, want 403 cross_site", res.Status, res.Body))
		}
		return check.Pass("403 cross_site on Sec-Fetch-Site: cross-site")
	}})
	crossSite403 := func(id, path, what string, headers map[string]string) check.Check {
		return check.Check{ID: id, Group: "csrf", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
			headers["X-Cauthy-Request"] = "1"
			res, err := c.Client.Fresh().PostJSON(path, map[string]any{}, headers)
			if err != nil {
				return check.Fail(err.Error())
			}
			e, why := errorOf(res)
			if res.Status != 403 || why != "" || e["code"] != "cross_site" {
				return check.Fail(fmt.Sprintf("POST %s with %s: %d %s, want 403 cross_site", path, what, res.Status, res.Body))
			}
			return check.Pass("403 cross_site on " + what)
		}}
	}
	reg.Add(crossSite403("csrf.sign_out_foreign_origin_403", "/sign-out", "a foreign Origin", map[string]string{"Origin": "https://evil.example"}))
	// The protocol: with no Origin, Sec-Fetch-Site must be absent or same-origin.
	reg.Add(crossSite403("csrf.fetch_site_same_site_403", "/sign-in/email", "Sec-Fetch-Site: same-site and no Origin", map[string]string{"Origin": "", "Sec-Fetch-Site": "same-site"}))
}
