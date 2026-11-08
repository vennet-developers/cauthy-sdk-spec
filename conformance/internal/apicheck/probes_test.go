package apicheck

import (
	"slices"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/oas"
)

func TestParseReadsProbes(t *testing.T) {
	f, err := Parse([]byte(testProbes))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Probes) != 3 || f.Probes[0].ID != "create" || !slices.Equal(f.Probes[0].Expect, Statuses{201}) {
		t.Fatalf("%+v", f.Probes)
	}
	if f.Probes[0].Capture["thing_id"] != "data.id" || f.Probes[1].Params["id"] != "{thing_id}" {
		t.Fatalf("%+v", f.Probes)
	}
}

func TestParseRefusesMalformedProbes(t *testing.T) {
	for name, src := range map[string]string{
		"version":       "version: 2\nprobes: []\n",
		"no id":         "version: 1\nprobes:\n  - {op: GET /x, expect: 200}\n",
		"twice":         "version: 1\nprobes:\n  - {id: a, op: GET /x, expect: 200}\n  - {id: a, op: GET /x, expect: 200}\n",
		"no expect":     "version: 1\nprobes:\n  - {id: a, op: GET /x}\n",
		"bad op":        "version: 1\nprobes:\n  - {id: a, op: get /x, expect: 200}\n",
		"missing param": "version: 1\nprobes:\n  - {id: a, op: GET /x/{id}, expect: 200}\n",
		"body and form": "version: 1\nprobes:\n  - {id: a, op: POST /x, expect: 200, body: {}, form: {a: b}}\n",
		"unknown field": "version: 1\nprobes:\n  - {id: a, op: GET /x, expect: 200, expects: 201}\n",
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestCoverageNamesWhatNoProbeSendsAndWhatTheDocumentLacks(t *testing.T) {
	d, err := oas.Load([]byte(testDoc))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := Parse([]byte(testProbes))
	if uncovered, unknown := Coverage(d, f); len(uncovered) != 0 || len(unknown) != 0 {
		t.Fatalf("%v %v", uncovered, unknown)
	}
	f.Probes = f.Probes[:1]
	f.Probes = append(f.Probes, Probe{ID: "ghost", Op: "GET /v1/ghosts", Expect: Statuses{200}})
	uncovered, unknown := Coverage(d, f)
	if !slices.Equal(uncovered, []string{"DELETE /v1/things/{id}", "GET /v1/things/{id}"}) || !slices.Equal(unknown, []string{"ghost (GET /v1/ghosts)"}) {
		t.Fatalf("%v %v", uncovered, unknown)
	}
}

func TestUnsetNamesAVariableNothingSets(t *testing.T) {
	f, _ := Parse([]byte(testProbes))
	if got := Unset(f, []string{"token"}); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	got := Unset(f, nil)
	if len(got) == 0 || !strings.Contains(got[0], "create uses {token}") {
		t.Fatalf("%v", got)
	}
	f.Probes[0], f.Probes[1] = f.Probes[1], f.Probes[0]
	if got := Unset(f, []string{"token"}); len(got) == 0 || !strings.Contains(got[0], "read uses {thing_id}") {
		t.Fatalf("a variable is set only by an earlier capture: %v", got)
	}
}

func TestExpand(t *testing.T) {
	got, err := expand("thing {run} of {tenant}", map[string]string{"run": "r1", "tenant": "acme"})
	if err != nil || got != "thing r1 of acme" {
		t.Fatal(got, err)
	}
	if _, err := expand("{nope}", nil); err == nil || !strings.Contains(err.Error(), "{nope}") {
		t.Fatal(err)
	}
	body, err := expandAny(map[string]any{"a": []any{"{run}", 1}}, map[string]string{"run": "r1"})
	if err != nil || body.(map[string]any)["a"].([]any)[0] != "r1" {
		t.Fatal(body, err)
	}
}
