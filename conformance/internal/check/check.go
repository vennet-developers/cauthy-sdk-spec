// Package check is the frame every conformance check hangs on: a check runs
// against a context and answers pass, fail, skip or n/a; the registry grades the
// answers by level.
package check

import (
	"fmt"
	"slices"
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

// The statuses a result or a graded line can carry. A check itself answers
// only pass, fail, skip or n/a; advisory is assigned by Run.
const (
	StatusPass = "pass"
	StatusFail = "fail"
	StatusSkip = "skip"
	// StatusNA is a check that does not apply to this backend (for example the
	// other half of a pair that depends on a tenant setting). It does not make a
	// run incomplete; a skip does.
	StatusNA       = "n/a"
	StatusAdvisory = "advisory"
)

type Result struct {
	Status string `json:"status"` // one of the Status constants
	Detail string `json:"detail"`
}

func Pass(detail string) Result { return Result{StatusPass, detail} }
func Fail(detail string) Result { return Result{StatusFail, detail} }
func Skip(detail string) Result { return Result{StatusSkip, detail} }
func NA(detail string) Result   { return Result{StatusNA, detail} }

type Check struct {
	ID    string
	Group string
	Level Level
	// NAPair is the ID of the check that applies when this one does not. Only a
	// check with a pair may answer n/a; anywhere else n/a hides a gap.
	NAPair string
	Run    func(*Ctx) Result
}

type Registry struct{ checks []Check }

// Add registers a check. An empty or repeated ID is a programming error and
// panics.
func (r *Registry) Add(c Check) {
	if c.ID == "" {
		panic("check: empty ID")
	}
	for _, have := range r.checks {
		if have.ID == c.ID {
			panic("check: duplicate ID " + c.ID)
		}
	}
	r.checks = append(r.checks, c)
}

// All returns a copy of the registered checks in the order they were added.
func (r *Registry) All() []Check { return slices.Clone(r.checks) }

// safeRun runs one check; a panic or a missing Run is a failure, not a crash.
func safeRun(c Check, ctx *Ctx) (res Result) {
	if c.Run == nil {
		return Fail("check has no Run")
	}
	defer func() {
		if p := recover(); p != nil {
			res = Fail(fmt.Sprintf("check panicked: %v", p))
		}
	}()
	res = c.Run(ctx)
	switch res.Status {
	case StatusPass, StatusFail, StatusSkip:
	case StatusNA:
		if c.NAPair == "" {
			res = Skip("n/a is only for paired checks: " + res.Detail)
		}
	default:
		res = Fail(fmt.Sprintf("invalid status %q: %s", res.Status, res.Detail))
	}
	return res
}

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
	defer ctx.Cleanup()
	rep := &Report{Level: level.String(), Results: []Graded{}}
	if ctx.Table != nil {
		rep.Protocol = ctx.Table.Version
	}
	if ctx.Client != nil {
		rep.Target = ctx.Client.Target
	}
	for _, c := range r.checks {
		if ctx.Client != nil && ctx.Client.Context().Err() != nil {
			// Canceled: the checks left are skipped, never graded.
			rep.Results = append(rep.Results, Graded{ID: c.ID, Group: c.Group, Level: c.Level.String(), Status: StatusSkip, Detail: "the run was canceled"})
			continue
		}
		res := safeRun(c, ctx)
		status := res.Status
		if status == StatusFail && c.Level > level {
			status = StatusAdvisory
		}
		rep.Results = append(rep.Results, Graded{ID: c.ID, Group: c.Group, Level: c.Level.String(), Status: status, Detail: res.Detail})
	}
	return rep
}

func (rep *Report) Passed() bool {
	for _, g := range rep.Results {
		if g.Status == StatusFail {
			return false
		}
	}
	return true
}

// Complete is false when a check at or below the run's level was skipped: the
// run proved less than it should, even if nothing failed.
func (rep *Report) Complete() bool { return rep.skipped() == 0 }

func levelOf(name string) Level {
	if name == Strict.String() {
		return Strict
	}
	return Basic
}

// skipped counts the skipped checks that the run's level required.
func (rep *Report) skipped() int {
	n := 0
	for _, g := range rep.Results {
		if g.Status == StatusSkip && levelOf(g.Level) <= levelOf(rep.Level) {
			n++
		}
	}
	return n
}
