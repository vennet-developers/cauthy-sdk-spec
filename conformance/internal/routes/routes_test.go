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
