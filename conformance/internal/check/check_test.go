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
