package checks

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
)

const sessionCookie = "cauthy_session"

// signIn signs the one account in on a fresh browser and returns it with the answer.
func signIn(c *check.Ctx, remember bool) (*client.Client, *client.Response, error) {
	if c.Email == "" || c.Password == "" {
		return nil, nil, fmt.Errorf("no credentials")
	}
	b := c.Client.Fresh()
	body := map[string]any{"email": c.Email, "password": c.Password}
	if remember {
		body["remember"] = true
	}
	res, err := b.PostJSON("/sign-in/email", body, map[string]string{"X-Cauthy-Request": "1"})
	return b, res, err
}

func sessionCookies(res *client.Response) []*http.Cookie {
	var out []*http.Cookie
	for _, ck := range res.SetCookies {
		if ck.Name == sessionCookie || strings.HasPrefix(ck.Name, sessionCookie+".") {
			out = append(out, ck)
		}
	}
	return out
}

func hasFields(obj map[string]any, fields ...string) (string, bool) {
	for _, f := range fields {
		if _, ok := obj[f]; !ok {
			return f, false
		}
	}
	return "", true
}

func RegisterSession(reg *check.Registry) {
	reg.Add(check.Check{ID: "session.unauthenticated_shape", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Fresh().Get("/session", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if res.Status != 200 || res.JSON == nil || res.JSON["status"] != "unauthenticated" || res.JSON["session"] != nil {
			return check.Fail(fmt.Sprintf("GET /session without cookies: %d %s", res.Status, res.Body))
		}
		return check.Pass(`{"session":null,"status":"unauthenticated"}`)
	}})
	reg.Add(check.Check{ID: "session.sign_in_email", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		_, res, err := signIn(c, false)
		if err != nil {
			return check.Skip(err.Error())
		}
		if res.Status != 200 || res.JSON == nil || res.JSON["status"] != "signed_in" {
			return check.Fail(fmt.Sprintf("POST /sign-in/email: %d %s", res.Status, res.Body))
		}
		sess, _ := res.JSON["session"].(map[string]any)
		if missing, ok := hasFields(sess, "user", "tenantId", "roles", "organizations", "expiresAt"); !ok {
			return check.Fail("signed_in answer lacks session." + missing)
		}
		if len(sessionCookies(res)) == 0 {
			return check.Fail("signed_in answer set no session cookie")
		}
		return check.Pass("signed_in with a PublicSession and a session cookie")
	}})
	reg.Add(check.Check{ID: "session.cookie_attributes", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		_, res, err := signIn(c, false)
		if err != nil {
			return check.Skip(err.Error())
		}
		cks := sessionCookies(res)
		if len(cks) == 0 {
			return check.Fail("no session cookie to inspect")
		}
		https := strings.HasPrefix(c.Client.Origin, "https://")
		for _, ck := range cks {
			switch {
			case !ck.HttpOnly:
				return check.Fail(ck.Name + " is not HttpOnly")
			case ck.SameSite != http.SameSiteLaxMode:
				return check.Fail(ck.Name + " is not SameSite=Lax")
			case ck.Path != "/":
				return check.Fail(ck.Name + " Path is not /")
			case https && !ck.Secure:
				return check.Fail(ck.Name + " is not Secure on an https origin")
			}
		}
		return check.Pass("HttpOnly; SameSite=Lax; Path=/; Secure when https")
	}})
	reg.Add(check.Check{ID: "session.authenticated_shape", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		b, _, err := signIn(c, false)
		if err != nil {
			return check.Skip(err.Error())
		}
		res, err := b.Get("/session", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if res.Status != 200 || res.JSON == nil || res.JSON["status"] != "authenticated" {
			return check.Fail(fmt.Sprintf("GET /session after sign-in: %d %s", res.Status, res.Body))
		}
		sess, _ := res.JSON["session"].(map[string]any)
		user, _ := sess["user"].(map[string]any)
		if missing, ok := hasFields(user, "id", "email", "name", "emailVerified", "restricted"); !ok {
			return check.Fail("session.user lacks " + missing)
		}
		return check.Pass("authenticated with user, tenantId, roles, organizations, expiresAt")
	}})
	reg.Add(check.Check{ID: "session.short_by_default", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		_, res, err := signIn(c, false)
		if err != nil {
			return check.Skip(err.Error())
		}
		for _, ck := range sessionCookies(res) {
			if ck.MaxAge > 0 || !ck.Expires.IsZero() {
				return check.Fail(ck.Name + " has Max-Age/Expires without remember; a default session ends with the browser")
			}
		}
		return check.Pass("no Max-Age without remember")
	}})
	reg.Add(check.Check{ID: "session.remember_needs_tenant", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		m, err := c.Client.Fresh().Get("/methods", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if m.JSON != nil && m.JSON["persistentSessions"] == true {
			return check.Skip("the tenant allows persistent sessions; see session.remember_when_allowed")
		}
		_, res, err := signIn(c, true)
		if err != nil {
			return check.Skip(err.Error())
		}
		for _, ck := range sessionCookies(res) {
			if ck.MaxAge > 0 {
				return check.Fail("remember:true produced Max-Age although the tenant does not allow persistent sessions")
			}
		}
		return check.Pass("remember is ignored when the tenant does not allow it")
	}})
	reg.Add(check.Check{ID: "session.remember_when_allowed", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		m, err := c.Client.Fresh().Get("/methods", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if m.JSON == nil || m.JSON["persistentSessions"] != true {
			return check.Skip("the tenant does not allow persistent sessions")
		}
		_, res, err := signIn(c, true)
		if err != nil {
			return check.Skip(err.Error())
		}
		for _, ck := range sessionCookies(res) {
			if ck.MaxAge != 2592000 {
				return check.Fail(fmt.Sprintf("%s Max-Age=%d, want 2592000 on remember", ck.Name, ck.MaxAge))
			}
		}
		return check.Pass("Max-Age=2592000 on remember when the tenant allows it")
	}})
	reg.Add(check.Check{ID: "session.sign_out", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		b, _, err := signIn(c, false)
		if err != nil {
			return check.Skip(err.Error())
		}
		res, err := b.PostJSON("/sign-out", map[string]any{}, map[string]string{"X-Cauthy-Request": "1"})
		if err != nil {
			return check.Fail(err.Error())
		}
		if res.Status != 200 || res.JSON == nil || res.JSON["status"] != "signed_out" {
			return check.Fail(fmt.Sprintf("POST /sign-out: %d %s", res.Status, res.Body))
		}
		cleared := false
		for _, ck := range sessionCookies(res) {
			if ck.MaxAge < 0 || ck.Value == "" {
				cleared = true
			}
		}
		if !cleared {
			return check.Fail("sign-out did not clear the session cookie (Max-Age=0)")
		}
		after, err := b.Get("/session", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if after.JSON == nil || after.JSON["status"] != "unauthenticated" {
			return check.Fail("still authenticated after sign-out")
		}
		return check.Pass("signed_out, cookie cleared, session gone")
	}})
}
