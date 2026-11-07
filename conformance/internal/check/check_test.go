package check

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRunsChecksAndGradesByLevel(t *testing.T) {
	reg := &Registry{}
	reg.Add(Check{ID: "protocol.unknown_404", Group: "protocol", Level: Basic, Run: func(*Ctx) Result { return Pass("404 on /nope") }})
	reg.Add(Check{ID: "strict.protocol_header", Group: "strict", Level: Strict, Run: func(*Ctx) Result { return Fail("no Cauthy-Protocol header") }})
	reg.Add(Check{ID: "session.sign_in", Group: "session", Level: Basic, Run: func(*Ctx) Result { return Skip("no credentials") }})

	if len(reg.All()) != 3 {
		t.Fatalf("All: %d", len(reg.All()))
	}

	rep := reg.Run(&Ctx{}, Basic)
	if rep.Level != "basic" || len(rep.Results) != 3 {
		t.Fatalf("report: %+v", rep)
	}
	if rep.Results[1].Status != "advisory" {
		t.Fatalf("a strict failure at basic is advisory, got %q", rep.Results[1].Status)
	}
	if !rep.Passed() {
		t.Fatal("basic must pass when only strict checks fail")
	}

	rep = reg.Run(&Ctx{}, Strict)
	if rep.Results[1].Status != "fail" || rep.Passed() {
		t.Fatal("at strict the same failure fails the run")
	}

	text := rep.Text()
	for _, want := range []string{"PASS     protocol.unknown_404", "FAIL     strict.protocol_header", "SKIP     session.sign_in", "1 passed, 1 failed, 1 skipped"} {
		if !strings.Contains(text, want) {
			t.Errorf("text report lacks %q:\n%s", want, text)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(rep.JSON(), &decoded); err != nil || decoded["level"] != "strict" {
		t.Fatalf("json report: %v %v", err, decoded)
	}
}

func TestPanicAndMalformedChecksFail(t *testing.T) {
	reg := &Registry{}
	reg.Add(Check{ID: "a.panics", Group: "a", Level: Basic, Run: func(*Ctx) Result { panic("boom") }})
	reg.Add(Check{ID: "a.no_run", Group: "a", Level: Basic})
	reg.Add(Check{ID: "a.bad_status", Group: "a", Level: Basic, Run: func(*Ctx) Result { return Result{Status: "advisory", Detail: "x"} }})
	rep := reg.Run(&Ctx{}, Basic)
	want := []string{"check panicked: boom", "check has no Run", `invalid status "advisory": x`}
	for i, w := range want {
		g := rep.Results[i]
		if g.Status != StatusFail || g.Detail != w {
			t.Errorf("%s: %+v, want fail %q", g.ID, g, w)
		}
	}
}

func TestAddRejectsEmptyAndDuplicateIDs(t *testing.T) {
	mustPanic := func(name string, f func()) {
		defer func() {
			if recover() == nil {
				t.Errorf("%s did not panic", name)
			}
		}()
		f()
	}
	reg := &Registry{}
	mustPanic("empty id", func() { reg.Add(Check{}) })
	reg.Add(Check{ID: "x.y"})
	mustPanic("duplicate id", func() { reg.Add(Check{ID: "x.y"}) })
}

func TestAllReturnsACopy(t *testing.T) {
	reg := &Registry{}
	reg.Add(Check{ID: "x.y"})
	reg.All()[0].ID = "changed"
	if reg.All()[0].ID != "x.y" {
		t.Fatal("All exposes the registry's slice")
	}
}

func TestPassedAndCompleteWithSkips(t *testing.T) {
	reg := &Registry{}
	reg.Add(Check{ID: "a.ok", Level: Basic, Run: func(*Ctx) Result { return Pass("") }})
	reg.Add(Check{ID: "a.skipped_strict", Level: Strict, Run: func(*Ctx) Result { return Skip("no") }})
	rep := reg.Run(&Ctx{}, Basic)
	if !rep.Passed() || !rep.Complete() {
		t.Fatal("a skipped strict check neither fails nor makes the run incomplete")
	}
	reg.Add(Check{ID: "a.skipped_basic", Level: Basic, Run: func(*Ctx) Result { return Skip("no") }})
	rep = reg.Run(&Ctx{}, Basic)
	if !rep.Passed() || rep.Complete() {
		t.Fatal("a skipped basic check passes but leaves the run incomplete")
	}
	if !strings.Contains(rep.Text(), "INCOMPLETE: 1 basic checks skipped") {
		t.Fatalf("text lacks INCOMPLETE:\n%s", rep.Text())
	}
}

func TestJSONFields(t *testing.T) {
	empty := (&Registry{}).Run(&Ctx{}, Basic)
	var d map[string]any
	if err := json.Unmarshal(empty.JSON(), &d); err != nil {
		t.Fatal(err)
	}
	if r, ok := d["results"].([]any); !ok || len(r) != 0 {
		t.Fatalf("results must be [] not null: %v", d["results"])
	}
	reg := &Registry{}
	reg.Add(Check{ID: "a.ok", Level: Basic, Run: func(*Ctx) Result { return Pass("") }})
	reg.Add(Check{ID: "a.skip", Level: Basic, Run: func(*Ctx) Result { return Skip("") }})
	if err := json.Unmarshal(reg.Run(&Ctx{}, Basic).JSON(), &d); err != nil {
		t.Fatal(err)
	}
	counts, _ := d["counts"].(map[string]any)
	if d["passed"] != true || d["complete"] != false || counts["pass"] != 1.0 || counts["skip"] != 1.0 || counts["fail"] != 0.0 || counts["advisory"] != 0.0 {
		t.Fatalf("json: %v", d)
	}
}
