package checks

import (
	"fmt"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
)

var validNext = map[string]bool{"done": true, "mfa": true, "verify_email": true, "code": true, "passkey": true, "redirect": true}

func RegisterStrict(reg *check.Registry) {
	reg.Add(check.Check{ID: "strict.protocol_header", Group: "strict", Level: check.Strict, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Fresh().Get("/session", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		want := fmt.Sprint(c.Table.Version)
		if got := res.Header.Get("Cauthy-Protocol"); got != want {
			return check.Fail(fmt.Sprintf("Cauthy-Protocol=%q, want %q", got, want))
		}
		return check.Pass("Cauthy-Protocol: " + want)
	}})
	reg.Add(check.Check{ID: "strict.request_header_required", Group: "strict", Level: check.Strict, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Fresh().PostJSON("/sign-in/email", map[string]any{"email": "a@example.com", "password": "x"}, map[string]string{"X-Cauthy-Request": ""})
		if err != nil {
			return check.Fail(err.Error())
		}
		e, why := errorOf(res)
		if res.Status != 403 || why != "" || e["code"] != "csrf_required" {
			return check.Fail(fmt.Sprintf("POST without X-Cauthy-Request: %d %s, want 403 csrf_required", res.Status, res.Body))
		}
		return check.Pass("403 csrf_required without X-Cauthy-Request")
	}})
	reg.Add(check.Check{ID: "strict.next_on_sign_in", Group: "strict", Level: check.Strict, Run: func(c *check.Ctx) check.Result {
		_, res, stop := signedIn(c, slotPlain, false)
		if stop != nil {
			return *stop
		}
		if res.JSON == nil || res.JSON["next"] == nil {
			return check.Fail("signed_in answer has no next field")
		}
		next, _ := res.JSON["next"].(string)
		if !validNext[next] {
			return check.Fail(fmt.Sprintf("next=%v is not one of done, mfa, verify_email, code, passkey, redirect", res.JSON["next"]))
		}
		return check.Pass(fmt.Sprintf("next=%v", res.JSON["next"]))
	}})
}
