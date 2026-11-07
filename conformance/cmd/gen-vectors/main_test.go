package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMakeKeysWritesMissingFilesOnly(t *testing.T) {
	dir := t.TempDir()
	if err := MakeKeys(dir); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(dir, KidA+".jwk.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(first, []byte("TEST ONLY")) {
		t.Fatal("a key file must say it is a test key")
	}
	if err := os.Remove(filepath.Join(dir, KidB+".jwk.json")); err != nil {
		t.Fatal(err)
	}
	if err := MakeKeys(dir); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(filepath.Join(dir, KidA+".jwk.json"))
	if !bytes.Equal(first, again) {
		t.Fatal("MakeKeys replaced an existing key")
	}
	keys, err := LoadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 4 || keys[KidWeak].N.BitLen() != 1024 || keys[KidA].N.BitLen() != 2048 {
		t.Fatalf("keys: %d", len(keys))
	}
}
