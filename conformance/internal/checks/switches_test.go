package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/admin"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

// switchCtx is a context whose backend reads its settings from the fake's
// own Cauthy, with an admin of that Cauthy.
func switchCtx(t *testing.T, k fake.Knobs) (*check.Ctx, *fake.Server) {
	t.Helper()
	ctx, srv := ctxFor(t, k)
	base := srv.StartCauthy("admin-token")
	ctx.Admin = admin.New(context.Background(), base, fake.Tenant, "admin-token", fake.ClientID)
	ctx.SwitchWait = time.Second
	return ctx, srv
}

func runSwitch(t *testing.T, id string, k fake.Knobs) (check.Result, *fake.Server) {
	t.Helper()
	ctx, srv := switchCtx(t, k)
	reg := &check.Registry{}
	RegisterSwitches(reg)
	for _, c := range reg.All() {
		if c.ID == id {
			res := c.Run(ctx)
			ctx.Cleanup()
			return res, srv
		}
	}
	t.Fatalf("no check %s", id)
	return check.Result{}, nil
}

var switchIDs = []string{"switches.sign_up", "switches.password", "switches.magic_link", "switches.passkeys", "switches.confirm_email", "switches.persistent_sessions"}

func TestEverySwitchPassesOnABackendThatFollowsCauthy(t *testing.T) {
	for _, id := range switchIDs {
		res, srv := runSwitch(t, id, fake.Knobs{})
		if res.Status != check.StatusPass {
			t.Errorf("%s: %s %s", id, res.Status, res.Detail)
		}
		// The tenant is as the check found it, with no account left behind.
		for _, k := range []string{"allow_signup", "allow_password", "allow_magic_link", "allow_passkeys", "confirm_email"} {
			want := k == "allow_signup" || k == "allow_password"
			if srv.Setting(k) != want {
				t.Errorf("%s left %s = %v", id, k, srv.Setting(k))
			}
		}
		if srv.ClientPersistent() || len(srv.Accounts()) != 0 {
			t.Errorf("%s left the client persistent=%v, accounts %v", id, srv.ClientPersistent(), srv.Accounts())
		}
	}
}

func TestEachSwitchFailsOnABackendThatIgnoresIt(t *testing.T) {
	for _, tc := range []struct {
		id   string
		k    fake.Knobs
		want string
	}{
		{"switches.sign_up", fake.Knobs{StaleSettings: true}, "/methods.signUp"},
		{"switches.sign_up", fake.Knobs{SignupAlwaysOpen: true}, "/methods.signUp"},
		{"switches.password", fake.Knobs{StaleSettings: true}, "/methods.passwordSignIn"},
		{"switches.password", fake.Knobs{PasswordAlwaysOffered: true}, "/methods.passwordSignIn"},
		{"switches.magic_link", fake.Knobs{MagicLinkNeverOffered: true}, "sign-in page"},
		{"switches.magic_link", fake.Knobs{StaleSettings: true}, "/methods.magicLink"},
		{"switches.passkeys", fake.Knobs{PasskeyAlwaysOffered: true}, "still offered one"},
		{"switches.confirm_email", fake.Knobs{ConfirmEmailIgnored: true}, "want 200 verification_required"},
		{"switches.persistent_sessions", fake.Knobs{StaleSettings: true}, "/methods.persistentSessions"},
		{"switches.persistent_sessions", fake.Knobs{PersistentAllowed: true}, "still said true"},
		{"switches.persistent_sessions", fake.Knobs{RememberIgnoresTenant: true}, "still made a long session"},
	} {
		res, srv := runSwitch(t, tc.id, tc.k)
		if res.Status != check.StatusFail || !strings.Contains(res.Detail, tc.want) {
			t.Errorf("%s with %+v: want a failure naming %q, got %s %s", tc.id, tc.k, tc.want, res.Status, res.Detail)
		}
		if len(srv.Accounts()) != 0 || srv.ClientPersistent() || srv.Setting("allow_password") != true {
			t.Errorf("%s with %+v did not put the tenant back", tc.id, tc.k)
		}
	}
}

func TestSwitchesSkipWithoutCauthy(t *testing.T) {
	reg := &check.Registry{}
	RegisterSwitches(reg)
	for _, id := range switchIDs {
		expect(t, reg, id, fake.Knobs{}, check.StatusSkip)
	}
}

func TestASwitchCauthyRefusesIsSkipped(t *testing.T) {
	ctx, _ := switchCtx(t, fake.Knobs{})
	ctx.Admin = admin.New(context.Background(), ctx.Admin.Base, fake.Tenant, "wrong-token", fake.ClientID)
	reg := &check.Registry{}
	RegisterSwitches(reg)
	res := reg.All()[0].Run(ctx)
	if res.Status != check.StatusSkip || !strings.Contains(res.Detail, "401") || strings.Contains(res.Detail, "wrong-token") {
		t.Fatalf("%s %s", res.Status, res.Detail)
	}
}

func TestThePersistentSwitchNeedsTheClient(t *testing.T) {
	ctx, _ := switchCtx(t, fake.Knobs{})
	ctx.Admin.ClientID = ""
	reg := &check.Registry{}
	RegisterSwitches(reg)
	for _, c := range reg.All() {
		if c.ID == "switches.persistent_sessions" {
			if res := c.Run(ctx); res.Status != check.StatusSkip || !strings.Contains(res.Detail, "--client-id") {
				t.Fatalf("%s %s", res.Status, res.Detail)
			}
		}
	}
}

// A backend that reads Cauthy on every /methods must not be polled into
// Cauthy's rate limit: the wait between reads grows from 200 ms to 2 s.
func TestPollingBacksOff(t *testing.T) {
	want := []time.Duration{200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond, 2 * time.Second, 2 * time.Second}
	d := time.Duration(0)
	for i, w := range want {
		if d = nextPoll(d); d != w {
			t.Fatalf("poll %d waits %s, want %s", i, d, w)
		}
	}
}
