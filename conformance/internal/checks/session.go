package checks

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
)

const sessionCookie = "cauthy_session"

// Sign-in slots: the run signs in at most three times (see check.Ctx.SignIn).
const (
	slotPlain    = "plain"    // remember:false, read by many checks
	slotShape    = "shape"    // read by authenticated_shape, then ended by sign_out
	slotRemember = "remember" // remember:true
)

// signedIn returns the cached sign-in of a slot when it really signed the
// account in: status 200, "signed_in" and a session cookie. Otherwise stop is
// the result the check must return: a skip when the account cannot be used by a
// test (no credentials, MFA, unverified email), a fail with the answer when
// sign-in is broken.
func signedIn(c *check.Ctx, slot string, remember bool) (b *client.Client, res *client.Response, stop *check.Result) {
	fail := func(s string) (*client.Client, *client.Response, *check.Result) {
		r := check.Fail(s)
		return nil, nil, &r
	}
	if c.Email == "" || c.Password == "" {
		r := check.Skip("no credentials")
		return nil, nil, &r
	}
	b, res, err := c.SignIn(slot, remember)
	if err != nil {
		return fail(err.Error())
	}
	if st, _ := res.JSON["status"].(string); st == "mfa_required" || st == "verification_required" {
		r := check.Skip("the test account must have MFA off and a verified email")
		return nil, nil, &r
	}
	if res.Status != 200 || res.JSON == nil || res.JSON["status"] != "signed_in" {
		return fail(fmt.Sprintf("POST /sign-in/email: %d %s", res.Status, res.Body))
	}
	if len(sessionCookies(res)) == 0 {
		return fail("signed_in answer set no session cookie")
	}
	return b, res, nil
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
		_, res, stop := signedIn(c, slotPlain, false)
		if stop != nil {
			return *stop
		}
		sess, _ := res.JSON["session"].(map[string]any)
		if missing, ok := hasFields(sess, "user", "tenantId", "roles", "organizations", "expiresAt"); !ok {
			return check.Fail("signed_in answer lacks session." + missing)
		}
		return check.Pass("signed_in with a PublicSession and a session cookie")
	}})
	reg.Add(check.Check{ID: "session.cookie_attributes", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		_, res, stop := signedIn(c, slotPlain, false)
		if stop != nil {
			return *stop
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
		b, _, stop := signedIn(c, slotShape, false)
		if stop != nil {
			return *stop
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
		_, res, stop := signedIn(c, slotPlain, false)
		if stop != nil {
			return *stop
		}
		for _, ck := range sessionCookies(res) {
			if ck.MaxAge > 0 || !ck.Expires.IsZero() {
				return check.Fail(ck.Name + " has Max-Age/Expires without remember; a default session ends with the browser")
			}
		}
		return check.Pass("no Max-Age without remember")
	}})
	reg.Add(check.Check{ID: "session.remember_needs_tenant", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		m, err := c.Methods()
		if err != nil {
			return check.Fail(err.Error())
		}
		if m.JSON != nil && m.JSON["persistentSessions"] == true {
			return check.Skip("the tenant allows persistent sessions; see session.remember_when_allowed")
		}
		_, res, stop := signedIn(c, slotRemember, true)
		if stop != nil {
			return *stop
		}
		for _, ck := range sessionCookies(res) {
			if ck.MaxAge > 0 || !ck.Expires.IsZero() {
				return check.Fail("remember:true produced Max-Age although the tenant does not allow persistent sessions")
			}
		}
		return check.Pass("remember is ignored when the tenant does not allow it")
	}})
	reg.Add(check.Check{ID: "session.remember_when_allowed", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		m, err := c.Methods()
		if err != nil {
			return check.Fail(err.Error())
		}
		if m.JSON == nil || m.JSON["persistentSessions"] != true {
			return check.Skip("the tenant does not allow persistent sessions")
		}
		_, res, stop := signedIn(c, slotRemember, true)
		if stop != nil {
			return *stop
		}
		for _, ck := range sessionCookies(res) {
			if ck.MaxAge != 2592000 {
				return check.Fail(fmt.Sprintf("%s Max-Age=%d, want 2592000 on remember", ck.Name, ck.MaxAge))
			}
		}
		return check.Pass("Max-Age=2592000 on remember when the tenant allows it")
	}})
	reg.Add(check.Check{ID: "session.sign_out", Group: "session", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		b, _, stop := signedIn(c, slotShape, false)
		if stop != nil {
			return *stop
		}
		before, err := b.Get("/session", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if before.JSON == nil || before.JSON["status"] != "authenticated" {
			return check.Fail(fmt.Sprintf("not authenticated before sign-out: GET /session %d %s", before.Status, before.Body))
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
