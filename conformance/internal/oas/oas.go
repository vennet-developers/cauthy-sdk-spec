// Package oas reads what the API check and the type generator need of an
// OpenAPI 3.0 document: its operations with their responses, and its schemas,
// with every $ref checked to resolve.
package oas

import (
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Doc is a loaded document.
type Doc struct {
	// Ops holds every operation by "METHOD /path", the path as the document writes it.
	Ops map[string]*Operation
	// Schemas holds components.schemas by name.
	Schemas map[string]*Schema
}

// Operation is one method on one path.
type Operation struct {
	Method      string               `yaml:"-"`
	Path        string               `yaml:"-"`
	OperationID string               `yaml:"operationId"`
	Tags        []string             `yaml:"tags"`
	Responses   map[string]*Response `yaml:"responses"`
	RequestBody *Body                `yaml:"requestBody"`
}

// Response is one documented answer. Content is empty for an answer with no body.
type Response struct {
	Ref         string            `yaml:"$ref"`
	Description string            `yaml:"description"`
	Content     map[string]*Media `yaml:"content"`
}

// Body is a request body.
type Body struct {
	Required bool              `yaml:"required"`
	Content  map[string]*Media `yaml:"content"`
}

// Media is one content type of a body.
type Media struct {
	Schema *Schema `yaml:"schema"`
}

// Schema is the part of an OpenAPI 3.0 schema object Cauthy's document uses.
type Schema struct {
	Ref                  string             `yaml:"$ref"`
	Type                 string             `yaml:"type"`
	Format               string             `yaml:"format"`
	Description          string             `yaml:"description"`
	Properties           map[string]*Schema `yaml:"properties"`
	Required             []string           `yaml:"required"`
	Items                *Schema            `yaml:"items"`
	AdditionalProperties *Extra             `yaml:"additionalProperties"`
	Enum                 []any              `yaml:"enum"`
	Nullable             bool               `yaml:"nullable"`
	AllOf                []*Schema          `yaml:"allOf"`
	OneOf                []*Schema          `yaml:"oneOf"`
	AnyOf                []*Schema          `yaml:"anyOf"`
	// PropertyOrder lists the names of Properties as the document writes them.
	PropertyOrder []string `yaml:"-"`
}

// UnmarshalYAML decodes a schema and keeps the order of its properties.
func (s *Schema) UnmarshalYAML(n *yaml.Node) error {
	type plain Schema
	if err := n.Decode((*plain)(s)); err != nil {
		return err
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value != "properties" {
			continue
		}
		props := n.Content[i+1]
		for j := 0; j+1 < len(props.Content); j += 2 {
			s.PropertyOrder = append(s.PropertyOrder, props.Content[j].Value)
		}
	}
	return nil
}

// Extra is additionalProperties: true, false, or a schema for the values.
type Extra struct {
	Allowed bool
	Schema  *Schema // nil for true and false
}

// UnmarshalYAML reads a boolean or a schema.
func (e *Extra) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&e.Allowed)
	}
	e.Allowed = true
	e.Schema = &Schema{}
	return n.Decode(e.Schema)
}

var methods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true}

// Load reads a document. A response's $ref is replaced by the response of
// components.responses it names; every other $ref must name a schema of
// components.schemas.
func Load(raw []byte) (*Doc, error) {
	var src struct {
		Paths      map[string]map[string]yaml.Node `yaml:"paths"`
		Components struct {
			Schemas   map[string]*Schema   `yaml:"schemas"`
			Responses map[string]*Response `yaml:"responses"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &src); err != nil {
		return nil, fmt.Errorf("oas: %w", err)
	}
	d := &Doc{Ops: map[string]*Operation{}, Schemas: src.Components.Schemas}
	if d.Schemas == nil {
		d.Schemas = map[string]*Schema{}
	}
	for path, item := range src.Paths {
		for method, node := range item {
			if !methods[method] {
				continue
			}
			op := &Operation{Method: strings.ToUpper(method), Path: path}
			if err := node.Decode(op); err != nil {
				return nil, fmt.Errorf("oas: %s %s: %w", op.Method, path, err)
			}
			d.Ops[op.Method+" "+path] = op
		}
	}
	for _, key := range d.Keys() {
		op := d.Ops[key]
		for status, r := range op.Responses {
			if r == nil {
				return nil, fmt.Errorf("oas: %s answers %s with nothing", key, status)
			}
			if r.Ref != "" {
				name, ok := strings.CutPrefix(r.Ref, "#/components/responses/")
				shared := src.Components.Responses[name]
				if !ok || shared == nil || shared.Ref != "" {
					return nil, fmt.Errorf("oas: %s answers %s with $ref %s, which names no response", key, status, r.Ref)
				}
				r = shared
				op.Responses[status] = shared
			}
			for ct, m := range r.Content {
				if err := d.checkRefs(m.Schema, 0); err != nil {
					return nil, fmt.Errorf("oas: %s answers %s %s: %w", key, status, ct, err)
				}
			}
		}
		if op.RequestBody != nil {
			for ct, m := range op.RequestBody.Content {
				if err := d.checkRefs(m.Schema, 0); err != nil {
					return nil, fmt.Errorf("oas: %s takes %s: %w", key, ct, err)
				}
			}
		}
	}
	for name, s := range d.Schemas {
		if err := d.checkRefs(s, 0); err != nil {
			return nil, fmt.Errorf("oas: schema %s: %w", name, err)
		}
	}
	return d, nil
}

// Keys lists the operations as "METHOD /path", sorted.
func (d *Doc) Keys() []string {
	keys := make([]string, 0, len(d.Ops))
	for k := range d.Ops {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// RefName is the schema a "#/components/schemas/<name>" reference names.
func RefName(ref string) (string, bool) {
	name, ok := strings.CutPrefix(ref, "#/components/schemas/")
	return name, ok && name != "" && !strings.Contains(name, "/")
}

// Resolve follows s's $ref, and the $ref of what it names, to a schema with none.
func (d *Doc) Resolve(s *Schema) (*Schema, error) {
	for i := 0; s != nil && s.Ref != ""; i++ {
		if i > 32 {
			return nil, fmt.Errorf("$ref %s goes round in circles", s.Ref)
		}
		name, ok := RefName(s.Ref)
		if !ok {
			return nil, fmt.Errorf("$ref %s is not #/components/schemas/<name>", s.Ref)
		}
		next, found := d.Schemas[name]
		if !found {
			return nil, fmt.Errorf("$ref %s names no schema", s.Ref)
		}
		s = next
	}
	return s, nil
}

// checkRefs answers an error for the first $ref under s that does not resolve.
// A named schema is checked on its own, so a reference is not followed.
func (d *Doc) checkRefs(s *Schema, depth int) error {
	if s == nil || depth > 64 {
		return nil
	}
	if s.Ref != "" {
		_, err := d.Resolve(s)
		return err
	}
	for _, name := range s.PropertyOrder {
		if err := d.checkRefs(s.Properties[name], depth+1); err != nil {
			return err
		}
	}
	for _, list := range [][]*Schema{s.AllOf, s.OneOf, s.AnyOf} {
		for _, x := range list {
			if err := d.checkRefs(x, depth+1); err != nil {
				return err
			}
		}
	}
	if err := d.checkRefs(s.Items, depth+1); err != nil {
		return err
	}
	if s.AdditionalProperties != nil {
		return d.checkRefs(s.AdditionalProperties.Schema, depth+1)
	}
	return nil
}
