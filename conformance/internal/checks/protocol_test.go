package checks

import (
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"
)

func protocolRegistry() *check.Registry {
	reg := &check.Registry{}
	RegisterProtocol(reg)
	return reg
}

func TestProtocolChecks(t *testing.T) {
	reg := protocolRegistry()
	expect(t, reg, "protocol.unknown_is_404", fake.Knobs{}, "pass")
	expect(t, reg, "protocol.trailing_slash", fake.Knobs{}, "pass")
	expect(t, reg, "protocol.trailing_slash", fake.Knobs{NoTrailingSlash: true}, "fail")
	expect(t, reg, "protocol.head_as_get", fake.Knobs{}, "pass")
	expect(t, reg, "protocol.get_on_post_is_405", fake.Knobs{}, "pass")
	expect(t, reg, "protocol.get_on_post_is_405", fake.Knobs{HeadNot405: true}, "fail")
	expect(t, reg, "protocol.no_store", fake.Knobs{}, "pass")
	expect(t, reg, "protocol.no_store", fake.Knobs{NoCacheControl: true}, "fail")
}

func TestProtocolChecksFailProofs(t *testing.T) {
	reg := protocolRegistry()
	expect(t, reg, "protocol.unknown_is_404", fake.Knobs{UnknownNot404: true}, "fail")
	expect(t, reg, "protocol.head_as_get", fake.Knobs{NoHead: true}, "fail")
	expect(t, reg, "protocol.no_store", fake.Knobs{JSONAsTextPlain: true}, "fail")
}

func detailOf(t *testing.T, reg *check.Registry, id string, k fake.Knobs) string {
	t.Helper()
	ctx, _ := ctxFor(t, k)
	for _, c := range reg.All() {
		if c.ID == id {
			return c.Run(ctx).Detail
		}
	}
	t.Fatalf("no check %s", id)
	return ""
}

func TestNoStoreNamesTheFirstAnswerThatLacksIt(t *testing.T) {
	if d := detailOf(t, protocolRegistry(), "protocol.no_store", fake.Knobs{NoCacheControl: true}); !strings.Contains(d, "GET /session") {
		t.Fatalf("detail does not name the answer: %s", d)
	}
}

// cauthy-auth 0.42 sends no-store on every JSON answer and redirect but not on
// its plain-text 404 and 405 (cauthy.ts: new Response('Not found', { status: 404 })).
// That is basic; no-store on every answer is strict.
func TestNoStoreAtBasicLeavesPlainTextAnswersToStrict(t *testing.T) {
	reg := protocolRegistry()
	expect(t, reg, "protocol.no_store", fake.Knobs{PlainTextCacheable: true}, "pass")
	expect(t, reg, "protocol.no_store", fake.Knobs{PlainTextCacheable: true, NoCacheControl: true}, "fail")
}

// A 404 is not plain text by itself: only the probes marked as plain-text are
// exempt at basic. A GET /session that answers 404 without no-store fails.
func TestNoStoreDoesNotExemptAJSONRouteAnswering404(t *testing.T) {
	expect(t, protocolRegistry(), "protocol.no_store", fake.Knobs{SessionUncacheable404: true}, "fail")
}
