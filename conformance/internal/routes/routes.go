// Package routes reads protocol/routes.yaml, the route table of auth-bff.
package routes

import (
	"bytes"
	"fmt"
	"os"
	"strings"

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
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
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
		if err := validate(r); err != nil {
			return nil, fmt.Errorf("routes.yaml: route %s: %w", r.ID, err)
		}
		t.byID[r.ID] = r
	}
	return &t, nil
}

var (
	validTypes = map[string]bool{"string": true, "email": true, "uuid": true, "number": true, "boolean": true, "object": true, "array": true}
	validNeeds = map[string]bool{"tenant": true, "session": true, "step": true, "crosssite": true, "json": true}
)

func validate(r *Route) error {
	if !strings.HasPrefix(r.Path, "/") {
		return fmt.Errorf("path %q must start with /", r.Path)
	}
	for _, n := range r.NeedsList {
		if !validNeeds[n] {
			return fmt.Errorf("unknown need %q", n)
		}
	}
	for _, params := range []map[string]Field{r.Query, r.Body} {
		for name, f := range params {
			if !validTypes[f.Type] {
				return fmt.Errorf("parameter %s: unknown type %q", name, f.Type)
			}
		}
	}
	for name, typ := range r.Success.Fields {
		if !validTypes[strings.TrimSuffix(typ, "?")] {
			return fmt.Errorf("success field %s: unknown type %q", name, typ)
		}
	}
	if r.Success.Redirect == (r.Success.Status > 0) {
		return fmt.Errorf("success must be exactly one of redirect: true or a status")
	}
	if len(r.Body) > 0 && !r.Needs("json") {
		return fmt.Errorf("body without json in needs")
	}
	if r.Method == "GET" && r.Needs("json") {
		return fmt.Errorf("json on a GET route")
	}
	return nil
}
