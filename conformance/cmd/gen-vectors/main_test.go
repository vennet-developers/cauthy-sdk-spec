package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/vectors"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/verify"
)

var vectorsDir = filepath.Join("..", "..", "..", "vectors")

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

func TestGenerateIsDeterministic(t *testing.T) {
	keys, err := LoadKeys(filepath.Join(vectorsDir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	j1, t1 := Generate(keys)
	j2, t2 := Generate(keys)
	if !bytes.Equal(j1, j2) || !bytes.Equal(t1, t2) {
		t.Fatal("two runs differ")
	}
}

func TestCommittedVectorsAreCurrent(t *testing.T) {
	keys, err := LoadKeys(filepath.Join(vectorsDir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	jwks, tokens := Generate(keys)
	for name, want := range map[string][]byte{"jwks.json": jwks, "tokens.json": tokens} {
		got, err := os.ReadFile(filepath.Join(vectorsDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("vectors/%s is stale: run go run ./cmd/gen-vectors ../vectors/keys ../vectors", name)
		}
	}
}

func TestCasesAreWellFormed(t *testing.T) {
	keys, err := LoadKeys(filepath.Join(vectorsDir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	_, tokens := Generate(keys)
	var f vectors.File
	if err := json.Unmarshal(tokens, &f); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	covered := map[verify.Reason]bool{}
	valid, withIssuers := 0, 0
	for _, c := range f.Cases {
		if seen[c.Name] {
			t.Errorf("%s: name used twice", c.Name)
		}
		seen[c.Name] = true
		if c.Token == "" || c.Description == "" || c.Rule == "" || c.Now != Now {
			t.Errorf("%s: incomplete", c.Name)
		}
		if len(c.Config.Issuers) > 0 {
			withIssuers++
		}
		switch c.Expect {
		case "valid":
			valid++
			if c.Reason != "" {
				t.Errorf("%s: a valid case has no reason", c.Name)
			}
		case "invalid":
			if !slices.Contains(verify.Reasons, verify.Reason(c.Reason)) {
				t.Errorf("%s: reason %q is not in the closed list", c.Name, c.Reason)
			}
			covered[verify.Reason(c.Reason)] = true
		default:
			t.Errorf("%s: expect %q", c.Name, c.Expect)
		}
	}
	for _, r := range verify.Reasons {
		if !covered[r] {
			t.Errorf("no vector refuses with %s", r)
		}
	}
	if valid < 10 {
		t.Errorf("%d valid cases: a verifier that refuses everything must fail the vectors", valid)
	}
	if withIssuers == 0 {
		t.Error("no case configures a list of issuers")
	}
}
