// Package runnertest gives other modules a backend that passes the suite at
// level basic (or strict, and with its fake Cauthy switches), to test code
// that wraps the runner.
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

// NewStrictBackend starts one that meets protocol 1 in full (level strict),
// the base of level switches.
func NewStrictBackend() *Backend {
	s := fake.New(fake.Knobs{Strict: true})
	return &Backend{URL: s.URL, Target: s.Target(), Email: s.Email, Password: s.Password, srv: s}
}

// Close stops the backend and closes its connections; its URL answers nothing after.
func (b *Backend) Close() { b.srv.Close() }

// SignIns says how many sessions the backend has opened.
func (b *Backend) SignIns() int { return b.srv.SignIns() }

// Cauthy is the fake Cauthy a Backend follows: its admin API flips the
// dashboard switches the checks at level switches exercise.
type Cauthy struct {
	URL      string // what --cauthy points at
	Tenant   string // the backend's workspace slug
	ClientID string // the backend's OAuth client
}

// StartCauthy starts the backend's fake Cauthy, which takes token as its
// admin bearer; Close stops it with the backend.
func (b *Backend) StartCauthy(token string) Cauthy {
	return Cauthy{URL: b.srv.StartCauthy(token), Tenant: fake.Tenant, ClientID: fake.ClientID}
}
