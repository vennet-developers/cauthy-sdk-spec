// Package apicheck sends probes to a running Cauthy and checks every answer
// against the public OpenAPI document: that its status is the one the probe
// expects and one the document lists, that its content type is documented,
// and that its body matches the documented schema. Problems name statuses and
// fields, never values: an answer may carry a secret.
package apicheck

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/oas"
)

// File is openapi/probes.yaml.
type File struct {
	Version int     `yaml:"version"`
	Probes  []Probe `yaml:"probes"`
}

// Probe is one request and what it must get back. Every string may name
// variables as {name}; see Run.
type Probe struct {
	ID string `yaml:"id"`
	// Op is the operation, as the document names it: "GET /v1/oauth/userinfo".
	Op string `yaml:"op"`
	// Auth names the variable whose value is sent as the bearer token; "" sends none.
	Auth string `yaml:"auth"`
	// Tenant sends X-Tenant-Key (the default); false leaves it out.
	Tenant  *bool             `yaml:"tenant"`
	Params  map[string]string `yaml:"params"`  // the path's {parameters}
	Query   map[string]string `yaml:"query"`   // the query string
	Headers map[string]string `yaml:"headers"` // more request headers
	Body    any               `yaml:"body"`    // sent as JSON
	Form    map[string]string `yaml:"form"`    // sent as application/x-www-form-urlencoded
	Expect  Statuses          `yaml:"expect"`  // the statuses that pass
	// Capture sets variables from the JSON answer: name → dotted path (data.id).
	Capture map[string]string `yaml:"capture"`
}

// Statuses is one status or a list of them.
type Statuses []int

// UnmarshalYAML takes 200 or [200, 403].
func (s *Statuses) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var one int
		if err := n.Decode(&one); err != nil {
			return err
		}
		*s = Statuses{one}
		return nil
	}
	var many []int
	if err := n.Decode(&many); err != nil {
		return err
	}
	*s = many
	return nil
}

func (s Statuses) String() string {
	parts := make([]string, len(s))
	for i, v := range s {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, " or ")
}

// Builtins are the variables every run sets: run, a random suffix new on
// every run, and tenant, the workspace the run speaks to.
var Builtins = []string{"run", "tenant"}

var (
	varRE       = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)
	pathParamRE = regexp.MustCompile(`\{([^}]+)\}`)
)

// Parse reads a probes file and checks its shape.
func Parse(raw []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("probes: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("probes: version must be 1, not %d", f.Version)
	}
	seen := map[string]bool{}
	for i, p := range f.Probes {
		where := fmt.Sprintf("probes: probe %d (%s)", i+1, p.ID)
		switch {
		case p.ID == "":
			return nil, fmt.Errorf("probes: probe %d has no id", i+1)
		case seen[p.ID]:
			return nil, fmt.Errorf("%s: the id is used twice", where)
		case len(p.Expect) == 0:
			return nil, fmt.Errorf("%s: expect is required", where)
		case p.Body != nil && p.Form != nil:
			return nil, fmt.Errorf("%s: body and form exclude each other", where)
		}
		method, path, ok := strings.Cut(p.Op, " ")
		if !ok || method == "" || method != strings.ToUpper(method) || !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("%s: op %q is not \"METHOD /path\"", where, p.Op)
		}
		for _, m := range pathParamRE.FindAllStringSubmatch(path, -1) {
			if _, ok := p.Params[m[1]]; !ok {
				return nil, fmt.Errorf("%s: params lacks %s", where, m[1])
			}
		}
		seen[p.ID] = true
	}
	return &f, nil
}

// Coverage lists the document's operations no probe sends, and the probes
// whose operation the document does not have.
func Coverage(d *oas.Doc, f *File) (uncovered, unknown []string) {
	probed := map[string]bool{}
	for _, p := range f.Probes {
		if d.Ops[p.Op] == nil {
			unknown = append(unknown, p.ID+" ("+p.Op+")")
		}
		probed[p.Op] = true
	}
	for _, k := range d.Keys() {
		if !probed[k] {
			uncovered = append(uncovered, k)
		}
	}
	return uncovered, unknown
}

// Unset lists the variables a probe uses before anything sets them: neither
// an input, a builtin, nor captured by an earlier probe.
func Unset(f *File, inputs []string) []string {
	set := map[string]bool{}
	for _, n := range inputs {
		set[n] = true
	}
	for _, n := range Builtins {
		set[n] = true
	}
	var out []string
	for _, p := range f.Probes {
		for _, name := range uses(p) {
			if !set[name] {
				out = append(out, fmt.Sprintf("%s uses {%s}, which nothing sets before it", p.ID, name))
			}
		}
		for name := range p.Capture {
			set[name] = true
		}
	}
	return out
}

// uses lists the variables a probe reads, sorted.
func uses(p Probe) []string {
	texts := stringsIn(p.Body)
	if p.Auth != "" {
		texts = append(texts, "{"+p.Auth+"}")
	}
	for _, m := range []map[string]string{p.Params, p.Query, p.Headers, p.Form} {
		for _, v := range m {
			texts = append(texts, v)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range texts {
		for _, m := range varRE.FindAllStringSubmatch(t, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	sort.Strings(out)
	return out
}

func stringsIn(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case map[string]any:
		var out []string
		for _, x := range t {
			out = append(out, stringsIn(x)...)
		}
		return out
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, stringsIn(x)...)
		}
		return out
	}
	return nil
}

// expand replaces every {name} in s with vars[name].
func expand(s string, vars map[string]string) (string, error) {
	missing := ""
	out := varRE.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		v, ok := vars[name]
		if !ok && missing == "" {
			missing = name
		}
		return v
	})
	if missing != "" {
		return "", fmt.Errorf("{%s} is not set", missing)
	}
	return out, nil
}

// expandAny expands every string inside a body.
func expandAny(v any, vars map[string]string) (any, error) {
	switch t := v.(type) {
	case string:
		return expand(t, vars)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			e, err := expandAny(x, vars)
			if err != nil {
				return nil, err
			}
			out[k] = e
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			e, err := expandAny(x, vars)
			if err != nil {
				return nil, err
			}
			out[i] = e
		}
		return out, nil
	}
	return v, nil
}
