// Package check is the frame every conformance check hangs on: a check runs
// against a context and answers pass, fail or skip; the registry grades the
// answers by level.
package check

import (
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

type Level int

const (
	Basic Level = iota
	Strict
)

func (l Level) String() string {
	if l == Strict {
		return "strict"
	}
	return "basic"
}

// Ctx is what a check receives: the target, the table and the one account.
type Ctx struct {
	Client   *client.Client
	Table    *routes.Table
	Email    string
	Password string
	JWKSPath string // "" when the backend is not in contract mode
}

type Result struct {
	Status string `json:"status"` // pass | fail | skip | advisory
	Detail string `json:"detail"`
}

func Pass(detail string) Result { return Result{"pass", detail} }
func Fail(detail string) Result { return Result{"fail", detail} }
func Skip(detail string) Result { return Result{"skip", detail} }

type Check struct {
	ID    string
	Group string
	Level Level
	Run   func(*Ctx) Result
}

type Registry struct{ checks []Check }

func (r *Registry) Add(c Check) { r.checks = append(r.checks, c) }

// All returns the registered checks in the order they were added.
func (r *Registry) All() []Check { return r.checks }

type Graded struct {
	ID     string `json:"id"`
	Group  string `json:"group"`
	Level  string `json:"level"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Report struct {
	Protocol int      `json:"protocol"`
	Level    string   `json:"level"`
	Target   string   `json:"target"`
	Results  []Graded `json:"results"`
}

// Run executes every check. A failing check above the requested level is
// reported as advisory and does not fail the run.
func (r *Registry) Run(ctx *Ctx, level Level) *Report {
	rep := &Report{Level: level.String()}
	if ctx.Table != nil {
		rep.Protocol = ctx.Table.Version
	}
	if ctx.Client != nil {
		rep.Target = ctx.Client.Target
	}
	for _, c := range r.checks {
		res := c.Run(ctx)
		status := res.Status
		if status == "fail" && c.Level > level {
			status = "advisory"
		}
		rep.Results = append(rep.Results, Graded{ID: c.ID, Group: c.Group, Level: c.Level.String(), Status: status, Detail: res.Detail})
	}
	return rep
}

func (rep *Report) Passed() bool {
	for _, g := range rep.Results {
		if g.Status == "fail" {
			return false
		}
	}
	return true
}
