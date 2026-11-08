package oas

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"time"
)

// Validate checks a value as encoding/json decodes it into an any against s,
// and lists what does not match, each as "<where>: <what>", where being a path
// such as $.data.items[0].id. It never quotes a value, since an answer may
// carry a secret. A field the schema does not document is a problem unless the
// schema takes extra fields (additionalProperties).
func (d *Doc) Validate(v any, s *Schema) []string {
	var out []string
	d.validate(v, s, "$", &out, 0)
	return out
}

// merged is a schema with its $ref resolved and its allOf folded in.
type merged struct {
	typ, format   string
	enum          []any
	nullable      bool
	props         map[string]*Schema
	declaresProps bool
	required      []string
	extra         *Extra
	items         *Schema
	alts          []*Schema // oneOf and anyOf
}

func (d *Doc) merge(s *Schema, m *merged, depth int) error {
	if depth > 64 {
		return fmt.Errorf("the schema nests deeper than 64")
	}
	s, err := d.Resolve(s)
	if err != nil || s == nil {
		return err
	}
	if m.typ == "" {
		m.typ = s.Type
	}
	if m.format == "" {
		m.format = s.Format
	}
	if m.enum == nil {
		m.enum = s.Enum
	}
	m.nullable = m.nullable || s.Nullable
	if s.Properties != nil {
		m.declaresProps = true
		if m.props == nil {
			m.props = map[string]*Schema{}
		}
		for k, p := range s.Properties {
			if _, have := m.props[k]; !have {
				m.props[k] = p
			}
		}
	}
	m.required = append(m.required, s.Required...)
	if m.extra == nil {
		m.extra = s.AdditionalProperties
	}
	if m.items == nil {
		m.items = s.Items
	}
	m.alts = append(m.alts, s.OneOf...)
	m.alts = append(m.alts, s.AnyOf...)
	for _, part := range s.AllOf {
		if err := d.merge(part, m, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (d *Doc) validate(v any, s *Schema, at string, out *[]string, depth int) {
	add := func(format string, a ...any) { *out = append(*out, at+": "+fmt.Sprintf(format, a...)) }
	var m merged
	if err := d.merge(s, &m, depth); err != nil {
		add("%v", err)
		return
	}
	if v == nil {
		if m.typ != "" && !m.nullable {
			add("null, but the schema is not nullable")
		}
		return
	}
	if len(m.alts) > 0 {
		matched := false
		for _, alt := range m.alts {
			var p []string
			d.validate(v, alt, at, &p, depth+1)
			if len(p) == 0 {
				matched = true
				break
			}
		}
		if !matched {
			add("matches none of the schema's oneOf/anyOf alternatives")
		}
		if m.typ == "" && !m.declaresProps {
			return
		}
	}
	if len(m.enum) > 0 && !inEnum(v, m.enum) {
		add("a value outside the schema's enum")
	}
	switch m.typ {
	case "string":
		str, ok := v.(string)
		if !ok {
			add("want a string, got %s", kind(v))
			return
		}
		if problem := badFormat(str, m.format); problem != "" {
			add("%s", problem)
		}
	case "integer":
		if f, ok := v.(float64); !ok || f != math.Trunc(f) {
			add("want an integer, got %s", kind(v))
		}
	case "number":
		if _, ok := v.(float64); !ok {
			add("want a number, got %s", kind(v))
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			add("want a boolean, got %s", kind(v))
		}
	case "array":
		list, ok := v.([]any)
		if !ok {
			add("want an array, got %s", kind(v))
			return
		}
		if m.items != nil {
			for i, x := range list {
				d.validate(x, m.items, fmt.Sprintf("%s[%d]", at, i), out, depth+1)
			}
		}
	case "object", "":
		obj, ok := v.(map[string]any)
		if !ok {
			if m.typ == "object" || m.declaresProps {
				add("want an object, got %s", kind(v))
			}
			return
		}
		seen := map[string]bool{}
		for _, r := range m.required {
			if _, has := obj[r]; !has && !seen[r] {
				add("lacks the required field %q", r)
			}
			seen[r] = true
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if p, documented := m.props[k]; documented {
				d.validate(obj[k], p, at+"."+k, out, depth+1)
				continue
			}
			switch {
			case m.extra != nil && m.extra.Schema != nil:
				d.validate(obj[k], m.extra.Schema, at+"."+k, out, depth+1)
			case m.extra != nil && m.extra.Allowed:
			case m.extra != nil:
				add("has the field %q, which the schema forbids", k)
			case m.declaresProps:
				add("has the field %q, which the schema does not document", k)
			}
		}
	default:
		add("the schema has the unknown type %q", m.typ)
	}
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// badFormat checks the two formats whose drift breaks a client: date-time and uuid.
func badFormat(s, format string) string {
	switch format {
	case "date-time":
		if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
			return "a string that is not a date-time (RFC 3339)"
		}
	case "uuid":
		if !uuidRE.MatchString(s) {
			return "a string that is not a UUID"
		}
	}
	return ""
}

func inEnum(v any, enum []any) bool {
	for _, e := range enum {
		if fmt.Sprint(e) == fmt.Sprint(v) {
			return true
		}
	}
	return false
}

func kind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case float64:
		return "a number"
	case []any:
		return "an array"
	case map[string]any:
		return "an object"
	}
	return fmt.Sprintf("%T", v)
}
