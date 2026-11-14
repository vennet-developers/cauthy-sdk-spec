package checks

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
)

// SwitchSettings are the tenant settings the switch checks change through
// PUT /v1/settings/auth; a test keeps them in step with openapi/cauthy.yaml.
var SwitchSettings = []string{"allow_signup", "allow_password", "allow_magic_link", "allow_passkeys", "confirm_email", "verify_grace_days", "persistent_sessions"}

// Sign-in slots of the switch checks (see check.Ctx.SignIn): three more
// sign-ins than a run without --cauthy.
const (
	slotSwitchPassword = "switch-password"
	slotRememberOn     = "switch-remember-on"
	slotRememberOff    = "switch-remember-off"
)

var csrfHeader = map[string]string{"X-Cauthy-Request": "1"}

// RegisterSwitches adds the dashboard-switch checks. Each changes one of the
// tenant's settings in Cauthy, as an admin would in the dashboard, checks that
// the backend follows with no restart, changes it back, checks again, and puts
// the tenant back as it found it. They run last and need --cauthy.
func RegisterSwitches(reg *check.Registry) {
	reg.Add(check.Check{ID: "switches.sign_up", Group: "switches", Level: check.Switches, Run: restoring(switchSignUp)})
	reg.Add(check.Check{ID: "switches.password", Group: "switches", Level: check.Switches, Run: restoring(switchPassword)})
	reg.Add(check.Check{ID: "switches.magic_link", Group: "switches", Level: check.Switches, Run: restoring(switchMagicLink)})
	reg.Add(check.Check{ID: "switches.passkeys", Group: "switches", Level: check.Switches, Run: restoring(switchPasskeys)})
	reg.Add(check.Check{ID: "switches.confirm_email", Group: "switches", Level: check.Switches, Run: restoring(switchConfirmEmail)})
	reg.Add(check.Check{ID: "switches.persistent_sessions", Group: "switches", Level: check.Switches, Run: restoring(switchPersistent)})
}

// restoring skips a switch check with no Cauthy, and puts the tenant back
// after it runs; a tenant it cannot put back fails the check.
func restoring(run func(*check.Ctx) check.Result) func(*check.Ctx) check.Result {
	return func(c *check.Ctx) (res check.Result) {
		if c.Admin == nil {
			return check.Skip("needs --cauthy and an admin token")
		}
		// Deferred, so a check that panics still leaves the tenant as found
		// for the checks after it.
		defer func() {
			if errs := c.Admin.Restore(); len(errs) > 0 && res.Status != "" {
				res = check.Fail(fmt.Sprintf("%s; and putting the tenant back failed: %v", res.Detail, errs))
			}
		}()
		return run(c)
	}
}

func wait(c *check.Ctx) time.Duration {
	if c.SwitchWait > 0 {
		return c.SwitchWait
	}
	return 10 * time.Second
}

// nextPoll is the wait before the next read of /methods: 200 ms, doubling up
// to 2 s, so a backend that reads Cauthy on every /methods is not polled into
// Cauthy's rate limit.
func nextPoll(d time.Duration) time.Duration {
	if d == 0 {
		return 200 * time.Millisecond
	}
	return min(2*d, 2*time.Second)
}

// methodsUntil reads /methods on a fresh browser until ok holds or the wait
// is over, and answers the last answer and whether ok held.
func methodsUntil(c *check.Ctx, ok func(map[string]any) bool) (map[string]any, bool, error) {
	deadline := time.Now().Add(wait(c))
	var pause time.Duration
	for {
		res, err := c.Client.Fresh().Get("/methods", nil)
		if err != nil {
			return nil, false, err
		}
		if res.Status != 200 || res.JSON == nil {
			return nil, false, fmt.Errorf("GET /methods: %d", res.Status)
		}
		if ok(res.JSON) {
			return res.JSON, true, nil
		}
		if time.Now().After(deadline) {
			return res.JSON, false, nil
		}
		pause = nextPoll(pause)
		select {
		case <-c.Client.Context().Done():
			return res.JSON, false, c.Client.Context().Err()
		case <-time.After(pause):
		}
	}
}

// flip changes settings in Cauthy and waits for /methods.field to say want.
// stop is the result the check must return when it could not.
func flip(c *check.Ctx, changes map[string]any, field string, want bool) *check.Result {
	if err := c.Admin.Set(changes); err != nil {
		r := check.Skip("Cauthy refused the switch: " + err.Error())
		return &r
	}
	return follows(c, fmt.Sprintf("%v", changes), field, want)
}

// follows waits for /methods.field to say want.
func follows(c *check.Ctx, what, field string, want bool) *check.Result {
	_, ok, err := methodsUntil(c, func(m map[string]any) bool { return m[field] == want })
	if err != nil {
		r := check.Fail(err.Error())
		return &r
	}
	if !ok {
		r := check.Fail(fmt.Sprintf("%s in Cauthy, and /methods.%s still did not say %v after %s: the backend does not follow the dashboard", what, field, want, wait(c)))
		return &r
	}
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// signUp signs a new account up with a fresh address on a fresh browser,
// and tells the admin to delete it afterwards.
func signUp(c *check.Ctx) (*client.Response, error) {
	email := "switch-" + randomHex(6) + "@example.com"
	c.Admin.Made(email)
	return c.Client.Fresh().PostJSON("/sign-up/email", map[string]any{
		"email": email, "password": "Sw1tch-" + randomHex(16) + "!", "name": "Switch Check",
	}, csrfHeader)
}

func switchSignUp(c *check.Ctx) check.Result {
	if stop := flip(c, map[string]any{"allow_signup": false}, "signUp", false); stop != nil {
		return *stop
	}
	res, err := signUp(c)
	if err != nil {
		return check.Fail(err.Error())
	}
	if res.Status != 403 {
		return check.Fail(fmt.Sprintf("sign-ups closed in Cauthy, and POST /sign-up/email answered %d, want 403", res.Status))
	}
	if stop := flip(c, map[string]any{"allow_signup": true}, "signUp", true); stop != nil {
		return *stop
	}
	return check.Pass("sign-ups closed then opened in Cauthy: /methods.signUp and /sign-up/email followed")
}

func switchPassword(c *check.Ctx) check.Result {
	if c.Email == "" || c.Password == "" {
		return check.Skip("no credentials")
	}
	// Cauthy keeps one way in: a sign-in link stands in while passwords are off.
	if stop := flip(c, map[string]any{"allow_magic_link": true, "allow_password": false}, "passwordSignIn", false); stop != nil {
		return *stop
	}
	res, err := c.Client.Fresh().PostJSON("/sign-in/email", map[string]any{"email": c.Email, "password": c.Password}, csrfHeader)
	if err != nil {
		return check.Fail(err.Error())
	}
	if res.Status == 200 && res.JSON != nil && res.JSON["status"] == "signed_in" {
		return check.Fail("passwords off in Cauthy, and a password still signed in")
	}
	if stop := flip(c, map[string]any{"allow_password": true}, "passwordSignIn", true); stop != nil {
		return *stop
	}
	if _, _, stop := signedIn(c, slotSwitchPassword, false); stop != nil {
		return *stop
	}
	return check.Pass("passwords off then on in Cauthy: /methods.passwordSignIn and /sign-in/email followed")
}

func switchMagicLink(c *check.Ctx) check.Result {
	if stop := flip(c, map[string]any{"allow_magic_link": true}, "magicLink", true); stop != nil {
		if stop.Status == check.StatusFail {
			stop.Detail += " (a sign-in link needs the application to name its sign-in page)"
		}
		return *stop
	}
	if stop := flip(c, map[string]any{"allow_magic_link": false}, "magicLink", false); stop != nil {
		return *stop
	}
	return check.Pass("sign-in links on then off in Cauthy: /methods.magicLink followed")
}

func switchPasskeys(c *check.Ctx) check.Result {
	if err := c.Admin.Set(map[string]any{"allow_passkeys": true}); err != nil {
		return check.Skip("Cauthy refused the switch: " + err.Error())
	}
	if err := c.Admin.Set(map[string]any{"allow_passkeys": false}); err != nil {
		return check.Skip("Cauthy refused the switch: " + err.Error())
	}
	none := func(m map[string]any) bool {
		return m["passkey"] != true && m["passkeyHere"] != true && m["passkeyOnCauthy"] != true
	}
	_, ok, err := methodsUntil(c, none)
	if err != nil {
		return check.Fail(err.Error())
	}
	if !ok {
		return check.Fail(fmt.Sprintf("passkeys off in Cauthy, and /methods still offered one after %s", wait(c)))
	}
	// Where passkeys run when on depends on the workspace's passkey domain:
	// that direction is not graded.
	return check.Pass("passkeys off in Cauthy: /methods offered none")
}

func switchConfirmEmail(c *check.Ctx) check.Result {
	if stop := flip(c, map[string]any{"allow_signup": true, "confirm_email": true, "verify_grace_days": 0}, "signUp", true); stop != nil {
		return *stop
	}
	res, err := signUp(c)
	if err != nil {
		return check.Fail(err.Error())
	}
	if res.Status != 200 || res.JSON == nil || res.JSON["status"] != "verification_required" {
		return check.Fail(fmt.Sprintf("addresses must be confirmed in Cauthy, and POST /sign-up/email answered %d %v, want 200 verification_required", res.Status, res.JSON["status"]))
	}
	if len(sessionCookies(res)) > 0 {
		return check.Fail("addresses must be confirmed in Cauthy, and the sign-up set a session cookie before the address was confirmed")
	}
	if err := c.Admin.Set(map[string]any{"confirm_email": false}); err != nil {
		return check.Skip("Cauthy refused the switch: " + err.Error())
	}
	// No field of /methods says it: the next sign-up shows it.
	res, err = signUp(c)
	if err != nil {
		return check.Fail(err.Error())
	}
	if res.Status != 200 || res.JSON == nil || res.JSON["status"] != "signed_in" || len(sessionCookies(res)) == 0 {
		return check.Fail(fmt.Sprintf("addresses need no confirming in Cauthy, and POST /sign-up/email answered %d %v, want 200 signed_in with a session", res.Status, res.JSON["status"]))
	}
	return check.Pass("confirm_email on then off in Cauthy: /sign-up/email held then signed the account in")
}

func long(res *client.Response) bool {
	for _, ck := range sessionCookies(res) {
		if ck.MaxAge > 0 || !ck.Expires.IsZero() {
			return true
		}
	}
	return false
}

func switchPersistent(c *check.Ctx) check.Result {
	if c.Email == "" || c.Password == "" {
		return check.Skip("no credentials")
	}
	if err := c.Admin.Set(map[string]any{"persistent_sessions": true}); err != nil {
		return check.Skip("Cauthy refused the switch: " + err.Error())
	}
	if stop := follows(c, "persistent sessions on for the workspace", "persistentSessions", true); stop != nil {
		return *stop
	}
	_, res, stop := signedIn(c, slotRememberOn, true)
	if stop != nil {
		return *stop
	}
	if !long(res) {
		return check.Fail("persistent sessions on for the workspace and remember:true, and the session cookie has no Max-Age")
	}
	if err := c.Admin.Set(map[string]any{"persistent_sessions": false}); err != nil {
		return check.Skip("Cauthy refused the switch: " + err.Error())
	}
	_, ok, err := methodsUntil(c, func(m map[string]any) bool { return m["persistentSessions"] != true })
	if err != nil {
		return check.Fail(err.Error())
	}
	if !ok {
		return check.Fail(fmt.Sprintf("persistent sessions off for the workspace, and /methods.persistentSessions still said true after %s", wait(c)))
	}
	_, res, stop = signedIn(c, slotRememberOff, true)
	if stop != nil {
		return *stop
	}
	if long(res) {
		return check.Fail("persistent sessions off for the workspace, and remember:true still made a long session cookie")
	}
	return check.Pass("persistent sessions on then off for the workspace: /methods.persistentSessions and the cookie followed")
}
