package apicheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/oas"
)

// knobs make the test API wrong in one way each.
type knobs struct {
	extraField, missingName, createAnswers200, bodyOnDelete, textPlain bool
}

func testAPI(t *testing.T, k knobs) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret-token" || r.Header.Get("X-Tenant-Key") != "acme" {
			w.WriteHeader(401)
			return
		}
		thing := map[string]any{"id": "t1", "name": "a thing"}
		if k.extraField {
			thing["owner"] = "s3cret-owner"
		}
		if k.missingName {
			delete(thing, "name")
		}
		ct := "application/json; charset=utf-8"
		if k.textPlain {
			ct = "text/plain"
		}
		w.Header().Set("Content-Type", ct)
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/things":
			status := 201
			if k.createAnswers200 {
				status = 200
			}
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]any{"data": thing})
		case "GET /v1/things/t1":
			json.NewEncoder(w).Encode(map[string]any{"data": thing})
		case "DELETE /v1/things/t1":
			if k.bodyOnDelete {
				w.WriteHeader(200)
				w.Write([]byte(`{"ok":true}`))
				return
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runAgainst(t *testing.T, k knobs) *Report {
	t.Helper()
	d, err := oas.Load([]byte(testDoc))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse([]byte(testProbes))
	if err != nil {
		t.Fatal(err)
	}
	srv := testAPI(t, k)
	return Run(context.Background(), Options{Base: srv.URL, Tenant: "acme", Doc: d, File: f, Vars: map[string]string{"token": "s3cret-token"}})
}

func problemsOf(rep *Report, id string) string {
	for _, r := range rep.Results {
		if r.ID == id {
			return strings.Join(r.Problems, "\n")
		}
	}
	return "no such probe"
}

func TestAnAPIThatMatchesItsDocumentPasses(t *testing.T) {
	rep := runAgainst(t, knobs{})
	if !rep.Passed {
		t.Fatal(rep.Text())
	}
	if out := rep.Text() + string(rep.JSON()); strings.Contains(out, "s3cret") {
		t.Fatalf("the report carries a secret:\n%s", out)
	}
}

func TestEachDriftFailsTheProbeThatMetIt(t *testing.T) {
	for name, tc := range map[string]struct {
		k       knobs
		probe   string
		problem string
	}{
		"undocumented field":  {knobs{extraField: true}, "read", `body $.data: has the field "owner", which the schema does not document`},
		"missing field":       {knobs{missingName: true}, "read", `body $.data: lacks the required field "name"`},
		"other status":        {knobs{createAnswers200: true}, "create", "answered 200; the probe expects 201"},
		"undocumented status": {knobs{createAnswers200: true}, "create", "which the document does not list"},
		"body where none":     {knobs{bodyOnDelete: true}, "remove", "answered 200 with a body"},
		"content type":        {knobs{textPlain: true}, "create", "as text/plain; the document lists application/json"},
	} {
		rep := runAgainst(t, tc.k)
		if rep.Passed || !strings.Contains(problemsOf(rep, tc.probe), tc.problem) {
			t.Errorf("%s: want %q on %s in:\n%s", name, tc.problem, tc.probe, rep.Text())
		}
		if out := rep.Text() + string(rep.JSON()); strings.Contains(out, "s3cret") {
			t.Errorf("%s: the report carries a value:\n%s", name, out)
		}
	}
}

func TestAFailedCaptureFailsTheProbesThatNeedIt(t *testing.T) {
	rep := runAgainst(t, knobs{createAnswers200: true})
	if !strings.Contains(problemsOf(rep, "read"), "params id: {thing_id} is not set") {
		t.Fatal(rep.Text())
	}
}

func TestACanceledRunSendsNothing(t *testing.T) {
	d, _ := oas.Load([]byte(testDoc))
	f, _ := Parse([]byte(testProbes))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep := Run(ctx, Options{Base: "http://127.0.0.1:1", Tenant: "acme", Doc: d, File: f})
	if rep.Passed || !strings.Contains(problemsOf(rep, "create"), "the run stopped") {
		t.Fatal(rep.Text())
	}
}
