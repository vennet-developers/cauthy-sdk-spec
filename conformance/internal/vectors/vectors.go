// Package vectors is the shape of vectors/tokens.json, shared by the
// generator that writes it and the tests that read it.
package vectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config is the verifier configuration a case runs with.
type Config struct {
	Issuer         string   `json:"issuer"`
	Issuers        []string `json:"issuers,omitempty"` // further accepted issuers
	Audience       string   `json:"audience"`
	Tenant         string   `json:"tenant"`
	AllowAnonymous bool     `json:"allow_anonymous,omitempty"`
	// AllowClientTokens accepts a client's own token (token_use).
	AllowClientTokens bool `json:"allow_client_tokens,omitempty"`
}

// Case is one token and the verdict every verifier must reach.
type Case struct {
	Name        string `json:"name"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Token       string `json:"token"`
	Now         int64  `json:"now"`
	Config      Config `json:"config"`
	Expect      string `json:"expect"`           // "valid" or "invalid"
	Reason      string `json:"reason,omitempty"` // set when Expect is "invalid"
}

// File is vectors/tokens.json.
type File struct {
	Comment       string `json:"comment"`
	Version       int    `json:"version"`
	LeewaySeconds int    `json:"leeway_seconds"`
	MaxTokenBytes int    `json:"max_token_bytes"`
	Cases         []Case `json:"cases"`
}

// Load reads tokens.json and jwks.json from dir.
func Load(dir string) (*File, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "tokens.json"))
	if err != nil {
		return nil, nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, fmt.Errorf("tokens.json: %w", err)
	}
	jwks, err := os.ReadFile(filepath.Join(dir, "jwks.json"))
	if err != nil {
		return nil, nil, err
	}
	return &f, jwks, nil
}
