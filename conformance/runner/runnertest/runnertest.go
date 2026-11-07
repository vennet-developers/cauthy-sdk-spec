// Package runnertest gives other modules a backend that passes the suite at
// level basic, to test code that wraps the runner.
package runnertest

import "github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/fake"

// Backend is a well-behaved auth-bff backend on a local port.
type Backend struct {
	URL      string // the application's origin
	Target   string // URL + /api/auth
	Email    string
	Password string
	srv      *fake.Server
}

// NewBackend starts one; Close stops it.
func NewBackend() *Backend {
	s := fake.New(fake.Knobs{})
	return &Backend{URL: s.URL, Target: s.Target(), Email: s.Email, Password: s.Password, srv: s}
}

// Close stops the backend and closes its connections; its URL answers nothing after.
func (b *Backend) Close() { b.srv.Close() }

// SignIns says how many sessions the backend has opened.
func (b *Backend) SignIns() int { return b.srv.SignIns() }
