package checks

import (
	"fmt"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
)

// errorOf reads {error:{code,message,field?}} and says what is wrong with it.
func errorOf(res *client.Response) (map[string]any, string) {
	if res.JSON == nil {
		return nil, "body is not a JSON object"
	}
	e, ok := res.JSON["error"].(map[string]any)
	if !ok {
		return nil, `body has no "error" object`
	}
	if _, ok := e["code"].(string); !ok {
		return nil, "error.code is not a string"
	}
	if _, ok := e["message"].(string); !ok {
		return nil, "error.message is not a string"
	}
	return e, ""
}

func RegisterErrors(reg *check.Registry) {
	hdr := map[string]string{"X-Cauthy-Request": "1"}
	reg.Add(check.Check{ID: "errors.not_json_is_bad_request", Group: "errors", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Fresh().PostRaw("/sign-in/email", []byte("not json"), hdr)
		if err != nil {
			return check.Fail(err.Error())
		}
		e, why := errorOf(res)
		if res.Status != 400 || why != "" || e["code"] != "bad_request" {
			return check.Fail(fmt.Sprintf("POST /sign-in/email with a non-JSON body: %d %s (%s)", res.Status, res.Body, why))
		}
		return check.Pass("400 bad_request on a non-JSON body")
	}})
	reg.Add(check.Check{ID: "errors.shape", Group: "errors", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Fresh().PostJSON("/sign-in/email", map[string]any{}, hdr)
		if err != nil {
			return check.Fail(err.Error())
		}
		if _, why := errorOf(res); why != "" {
			return check.Fail(fmt.Sprintf("error answer %d %s: %s", res.Status, res.Body, why))
		}
		return check.Pass(`{"error":{"code","message"}}`)
	}})
	reg.Add(check.Check{ID: "errors.validation_names_field", Group: "errors", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Fresh().PostJSON("/sign-in/email", map[string]any{"email": "not-an-email", "password": "x"}, hdr)
		if err != nil {
			return check.Fail(err.Error())
		}
		e, why := errorOf(res)
		if res.Status != 400 || why != "" || e["field"] != "email" {
			return check.Fail(fmt.Sprintf("invalid email: %d %s, want 400 with field=email", res.Status, res.Body))
		}
		return check.Pass("400 with field=email on an invalid email")
	}})
	reg.Add(check.Check{ID: "errors.wrong_password_is_not_200", Group: "errors", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		if c.Email == "" {
			return check.Skip("no credentials")
		}
		res, err := c.Client.Fresh().PostJSON("/sign-in/email", map[string]any{"email": c.Email, "password": "definitely-wrong-" + c.Password}, hdr)
		if err != nil {
			return check.Fail(err.Error())
		}
		e, why := errorOf(res)
		if res.Status != 401 || why != "" || e["code"] != "invalid_credentials" {
			return check.Fail(fmt.Sprintf("wrong password: %d %s, want 401 invalid_credentials (%s)", res.Status, res.Body, why))
		}
		if len(sessionCookies(res)) > 0 {
			return check.Fail("wrong password set a session cookie")
		}
		return check.Pass("401 invalid_credentials and no cookie")
	}})
	reg.Add(check.Check{ID: "errors.auth_route_401", Group: "errors", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		for _, path := range []string{"/me", "/me/organizations"} {
			res, err := c.Client.Fresh().Get(path, nil)
			if err != nil {
				return check.Fail(err.Error())
			}
			e, why := errorOf(res)
			if res.Status != 401 || why != "" || e["code"] != "unauthenticated" {
				return check.Fail(fmt.Sprintf("GET %s without a session: %d %s, want 401 unauthenticated", path, res.Status, res.Body))
			}
		}
		return check.Pass("401 unauthenticated on /me and /me/organizations")
	}})
}
