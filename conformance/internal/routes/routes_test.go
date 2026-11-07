package routes

import (
	"path/filepath"
	"testing"
)

func TestLoadsTheTable(t *testing.T) {
	table, err := Load(filepath.Join("..", "..", "..", "protocol", "routes.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if table.Version != 1 || table.Prefix != "/api/auth" {
		t.Fatalf("header: %+v", table)
	}
	if len(table.Routes) != 75 {
		t.Fatalf("want 75 routes, got %d", len(table.Routes))
	}
	r := table.ByID("sign-in.email")
	if r == nil || r.Method != "POST" || r.Path != "/sign-in/email" {
		t.Fatalf("sign-in.email: %+v", r)
	}
	if !r.Needs("crosssite") || !r.Needs("json") || r.Needs("session") {
		t.Fatalf("needs: %v", r.NeedsList)
	}
	if r.Body["email"].Type != "email" || !r.Body["email"].Required {
		t.Fatalf("body: %+v", r.Body)
	}
	if r.Success.Status != 200 || r.Success.Fields["status"] != "string" || r.Success.Fields["session"] != "object?" {
		t.Fatalf("success: %+v", r.Success)
	}
}

func TestRejectsDuplicateIDs(t *testing.T) {
	_, err := Parse([]byte("version: 1\nprefix: /api/auth\nroutes:\n  - {id: a.b, method: GET, path: /x, group: other, level: basic}\n  - {id: a.b, method: GET, path: /y, group: other, level: basic}\n"))
	if err == nil {
		t.Fatal("want an error for a duplicate id")
	}
}

func TestRejectsInvalidRoutes(t *testing.T) {
	base := func(route string) []byte {
		return []byte("version: 1\nprefix: /api/auth\nroutes:\n  - " + route + "\n")
	}
	cases := map[string]string{
		"unknown method":       `{id: a.b, method: PUT, path: /x, group: other, level: basic, success: {status: 200}}`,
		"failures retry":       `{id: a.b, method: GET, path: /x, group: other, level: basic, success: {status: 200}, failures: retry}`,
		"missing path":         `{id: a.b, method: GET, group: other, level: basic, success: {status: 200}}`,
		"path without slash":   `{id: a.b, method: GET, path: x, group: other, level: basic, success: {status: 200}}`,
		"typo key":             `{id: a.b, method: GET, path: /x, group: other, level: basic, need: [tenant], success: {status: 200}}`,
		"unknown body type":    `{id: a.b, method: POST, path: /x, group: other, level: basic, needs: [json], body: {a: {type: text}}, success: {status: 200}}`,
		"optional body type":   `{id: a.b, method: POST, path: /x, group: other, level: basic, needs: [json], body: {a: {type: "string?"}}, success: {status: 200}}`,
		"unknown success type": `{id: a.b, method: GET, path: /x, group: other, level: basic, success: {status: 200, fields: {a: "str?"}}}`,
		"unknown need":         `{id: a.b, method: GET, path: /x, group: other, level: basic, needs: [admin], success: {status: 200}}`,
		"success is empty":     `{id: a.b, method: GET, path: /x, group: other, level: basic, success: {}}`,
		"success is both":      `{id: a.b, method: GET, path: /x, group: other, level: basic, success: {status: 200, redirect: true}}`,
		"body without json":    `{id: a.b, method: POST, path: /x, group: other, level: basic, body: {a: {type: string}}, success: {status: 200}}`,
		"json on GET":          `{id: a.b, method: GET, path: /x, group: other, level: basic, needs: [json], success: {status: 200}}`,
	}
	for name, route := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(base(route))
			if err == nil {
				t.Fatal("want an error")
			}
		})
	}
	if _, err := Parse(base(`{id: a.b, method: GET, path: /x, group: other, level: basic, success: {status: 200, fields: {a: "string?"}}}`)); err != nil {
		t.Fatalf("a valid route was rejected: %v", err)
	}
}
