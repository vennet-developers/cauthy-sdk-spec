package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const doc = `openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /v1/me:
    get:
      responses:
        '200':
          description: me
          content:
            application/json:
              schema:
                type: object
                required: [data]
                properties:
                  data:
                    type: object
                    required: [id]
                    properties:
                      id: {type: string}
`

const probes = `version: 1
probes:
  - id: me
    op: GET /v1/me
    auth: token
    expect: 200
`

func files(t *testing.T, doc, probes string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	d, p := filepath.Join(dir, "cauthy.yaml"), filepath.Join(dir, "probes.yaml")
	if err := os.WriteFile(d, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(probes), 0o644); err != nil {
		t.Fatal(err)
	}
	return d, p
}

func api(t *testing.T, body string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret-token" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestPassesAgainstAnAPIThatMatches(t *testing.T) {
	d, p := files(t, doc, probes)
	report := filepath.Join(t.TempDir(), "report.json")
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"--cauthy", api(t, `{"data":{"id":"u1"}}`), "--tenant", "acme", "--doc", d, "--probes", p, "--json", report},
		[]string{"CAUTHY_API_CHECK_TOKEN=s3cret-token"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errOut.String())
	}
	raw, err := os.ReadFile(report)
	var rep struct{ Passed bool }
	if err != nil || json.Unmarshal(raw, &rep) != nil || !rep.Passed {
		t.Fatalf("%s %v", raw, err)
	}
	if strings.Contains(out.String()+errOut.String()+string(raw), "s3cret") {
		t.Fatal("a secret was printed")
	}
}

func TestFailsOnDrift(t *testing.T) {
	d, p := files(t, doc, probes)
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"--cauthy", api(t, `{"data":{"uid":"u1"}}`), "--tenant", "acme", "--doc", d, "--probes", p},
		[]string{"CAUTHY_API_CHECK_TOKEN=s3cret-token"}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), `lacks the required field "id"`) {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
}

func TestSetupErrorsExit2(t *testing.T) {
	d, p := files(t, doc, probes)
	uncovered, _ := files(t, doc+"  /v1/other:\n    get:\n      responses:\n        '200': {description: other}\n", probes)
	for name, args := range map[string][]string{
		"no cauthy":   {"--tenant", "acme", "--doc", d, "--probes", p},
		"no tenant":   {"--cauthy", "http://x", "--doc", d, "--probes", p},
		"no token":    {"--cauthy", "http://x", "--tenant", "acme", "--doc", d, "--probes", p},
		"uncovered":   {"--cauthy", "http://x", "--tenant", "acme", "--doc", uncovered, "--probes", p},
		"missing doc": {"--cauthy", "http://x", "--tenant", "acme", "--doc", "nope.yaml", "--probes", p},
		"bad var":     {"--cauthy", "http://x", "--tenant", "acme", "--var", "novalue"},
	} {
		var out, errOut bytes.Buffer
		env := []string{}
		if name != "no token" {
			env = append(env, "CAUTHY_API_CHECK_TOKEN=s3cret-token")
		}
		if code := run(context.Background(), args, env, &out, &errOut); code != 2 || errOut.Len() == 0 {
			t.Errorf("%s: exit %d, stderr %q", name, code, errOut.String())
		}
	}
}
