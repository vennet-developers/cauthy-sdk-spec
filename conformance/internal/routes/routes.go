// Package routes reads protocol/routes.yaml, the route table of auth-bff.
package routes

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Field struct {
	Type     string `yaml:"type"`
	Required bool   `yaml:"required"`
}

type Success struct {
	Status   int               `yaml:"status"`
	Fields   map[string]string `yaml:"fields"`
	Redirect bool              `yaml:"redirect"`
}

type Route struct {
	ID         string           `yaml:"id"`
	Method     string           `yaml:"method"`
	Path       string           `yaml:"path"`
	Group      string           `yaml:"group"`
	Level      string           `yaml:"level"`
	NeedsList  []string         `yaml:"needs"`
	Query      map[string]Field `yaml:"query"`
	Body       map[string]Field `yaml:"body"`
	Success    Success          `yaml:"success"`
	Sets       []string         `yaml:"sets"`
	Clears     []string         `yaml:"clears"`
	Errors     []string         `yaml:"errors"`
	Text       bool             `yaml:"text"`
	Stream     bool             `yaml:"stream"`
	Failures   string           `yaml:"failures"` // "" or "redirect"
	Deprecated bool             `yaml:"deprecated"`
}

// Needs says whether the route carries that requirement (tenant, session, step, crosssite, json).
func (r *Route) Needs(name string) bool {
	for _, n := range r.NeedsList {
		if n == name {
			return true
		}
	}
	return false
}

type Table struct {
	Version int      `yaml:"version"`
	Prefix  string   `yaml:"prefix"`
	Routes  []*Route `yaml:"routes"`
	byID    map[string]*Route
}

func (t *Table) ByID(id string) *Route { return t.byID[id] }

func Load(path string) (*Table, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Table, error) {
	var t Table
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("routes.yaml: %w", err)
	}
	t.byID = map[string]*Route{}
	for _, r := range t.Routes {
		switch {
		case r.ID == "" || r.Method == "" || r.Path == "" || r.Group == "" || r.Level == "":
			return nil, fmt.Errorf("routes.yaml: route %q lacks id, method, path, group or level", r.ID)
		case r.Method != "GET" && r.Method != "POST":
			return nil, fmt.Errorf("routes.yaml: route %s: method %q", r.ID, r.Method)
		case t.byID[r.ID] != nil:
			return nil, fmt.Errorf("routes.yaml: duplicate id %s", r.ID)
		case r.Failures != "" && r.Failures != "redirect":
			return nil, fmt.Errorf("routes.yaml: route %s: failures %q (only redirect)", r.ID, r.Failures)
		}
		t.byID[r.ID] = r
	}
	return &t, nil
}
