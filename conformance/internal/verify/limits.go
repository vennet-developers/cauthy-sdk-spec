package verify

import "time"

const (
	// MaxTokenBytes is the longest token a verifier reads (rule R1).
	MaxTokenBytes = 8192
	// DefaultLeeway is the clock tolerance when the configuration names none.
	DefaultLeeway = 30 * time.Second
	// MaxLeeway is the most clock tolerance a verifier accepts.
	MaxLeeway = 60 * time.Second
)
