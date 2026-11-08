package check

import (
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/admin"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

// Ctx is what a check receives: the target, the table and the one account.
// It also keeps the sign-ins and the /methods answer the checks share, so a
// run signs in at most three times and reads /methods once (backends rate-limit
// sign-ins). Checks run one after another; Ctx is not safe for concurrent use.
type Ctx struct {
	Client   *client.Client
	Table    *routes.Table
	Email    string
	Password string
	JWKSPath string // "" when the backend is not in contract mode
	// Admin changes the tenant's settings in Cauthy for the switch checks;
	// nil when the run has no Cauthy (--cauthy), and then they skip.
	Admin *admin.Client
	// SwitchWait is how long the backend has to follow a switch; 0 is 10 s.
	SwitchWait time.Duration

	signIns map[string]*signInEntry
	methods *methodsEntry
}

type signInEntry struct {
	browser *client.Client
	res     *client.Response
	err     error
}

type methodsEntry struct {
	res *client.Response
	err error
}

// SignIn signs the account in on a fresh browser the first time a slot is
// asked for and returns the same browser and answer afterwards. Slots keep
// checks that change the session (sign-out) apart from the ones that read it.
func (c *Ctx) SignIn(slot string, remember bool) (*client.Client, *client.Response, error) {
	if e, ok := c.signIns[slot]; ok {
		return e.browser, e.res, e.err
	}
	if c.signIns == nil {
		c.signIns = map[string]*signInEntry{}
	}
	e := &signInEntry{browser: c.Client.Fresh()}
	body := map[string]any{"email": c.Email, "password": c.Password}
	if remember {
		body["remember"] = true
	}
	e.res, e.err = e.browser.PostJSON("/sign-in/email", body, map[string]string{"X-Cauthy-Request": "1"})
	c.signIns[slot] = e
	return e.browser, e.res, e.err
}

// Methods reads GET /methods once on a fresh browser.
func (c *Ctx) Methods() (*client.Response, error) {
	if c.methods == nil {
		res, err := c.Client.Fresh().Get("/methods", nil)
		c.methods = &methodsEntry{res, err}
	}
	return c.methods.res, c.methods.err
}

// Cleanup signs out every session the run opened, best effort, so a run leaves
// none open, and puts back any tenant setting a switch check left changed (a
// switch check puts back its own; this is for a run stopped half way). It is
// safe to call twice.
func (c *Ctx) Cleanup() {
	for slot, e := range c.signIns {
		if e.err == nil && e.res != nil && e.res.Status == 200 {
			e.browser.PostJSON("/sign-out", map[string]any{}, map[string]string{"X-Cauthy-Request": "1"})
		}
		delete(c.signIns, slot)
	}
	if c.Admin != nil {
		c.Admin.Restore()
	}
}
