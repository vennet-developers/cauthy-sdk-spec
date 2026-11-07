package checks

import (
	"fmt"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
)

var validNext = map[string]bool{"done": true, "mfa": true, "verify_email": true, "code": true, "passkey": true, "redirect": true}

func RegisterStrict(reg *check.Registry) {
	reg.Add(check.Check{ID: "strict.protocol_header", Group: "strict", Level: check.Strict, Run: func(c *check.Ctx) check.Result {
		answers, err := sampleAnswers(c)
		if err != nil {
			return check.Fail(err.Error())
		}
		want := fmt.Sprint(c.Table.Version)
		for _, a := range answers {
			if got := a.res.Header.Get("Cauthy-Protocol"); got != want {
				return check.Fail(fmt.Sprintf("%s: Cauthy-Protocol=%q, want %q", a.label, got, want))
			}
		}
		return check.Pass(fmt.Sprintf("Cauthy-Protocol: %s on %d kinds of answer", want, len(answers)))
	}})
	reg.Add(check.Check{ID: "strict.request_header_required", Group: "strict", Level: check.Strict, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Fresh().PostJSON("/sign-in/email", map[string]any{}, map[string]string{"X-Cauthy-Request": ""})
		if err != nil {
			return check.Fail(err.Error())
		}
		e, why := errorOf(res)
		if res.Status != 403 || why != "" || e["code"] != "csrf_required" {
			return check.Fail(fmt.Sprintf("POST without X-Cauthy-Request: %d %s, want 403 csrf_required", res.Status, res.Body))
		}
		return check.Pass("403 csrf_required without X-Cauthy-Request")
	}})
	reg.Add(check.Check{ID: "strict.logout_exempt", Group: "strict", Level: check.Strict, Run: func(c *check.Ctx) check.Result {
		// A plain HTML form signs out and cannot add headers.
		res, err := c.Client.Fresh().PostRaw("/logout", nil, nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if e, why := errorOf(res); why == "" && res.Status == 403 && e["code"] == "csrf_required" {
			return check.Fail("POST /logout without X-Cauthy-Request answered 403 csrf_required; the route is exempt")
		}
		return check.Pass(fmt.Sprintf("POST /logout without X-Cauthy-Request answered %d", res.Status))
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
