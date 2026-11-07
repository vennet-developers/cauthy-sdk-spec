package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyTable(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml")
	if err := os.WriteFile(src, []byte("version: 1\r\nroutes: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyTable(src, dst); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "version: 1\r\nroutes: []\n" {
		t.Fatalf("%q: the copy must be byte for byte", got)
	}
	if err := copyTable(filepath.Join(dir, "missing.yaml"), dst); err == nil {
		t.Fatal("a missing source was accepted")
	}
}
