package oas

import (
	"encoding/json"
	"strings"
	"testing"
)

const schemas = `openapi: 3.0.3
info: {title: t, version: "1"}
paths: {}
components:
  schemas:
    Thing:
      type: object
      required: [id, name]
      properties:
        id: {type: string, format: uuid}
        name: {type: string}
        count: {type: integer}
        ratio: {type: number}
        on: {type: boolean}
        kind: {type: string, enum: [customer, supplier]}
        at: {type: string, format: date-time}
        note: {type: string, nullable: true}
        tags: {type: array, items: {type: string}}
        labels: {type: object, additionalProperties: {type: string}}
        free: {type: object, additionalProperties: true}
        closed: {type: object, properties: {a: {type: string}}, additionalProperties: false}
    Member:
      allOf:
        - $ref: '#/components/schemas/Base'
        - type: object
          required: [role]
          properties:
            role: {type: string}
    Base:
      type: object
      required: [user_id]
      properties:
        user_id: {type: string}
    Either:
      oneOf:
        - {type: string}
        - {type: object, required: [n], properties: {n: {type: integer}}}
    Anything: {}
`

func check(t *testing.T, schema, value string) []string {
	t.Helper()
	d := load(t, schemas)
	var v any
	if err := json.Unmarshal([]byte(value), &v); err != nil {
		t.Fatal(err)
	}
	return d.Validate(v, &Schema{Ref: "#/components/schemas/" + schema})
}

func TestAValidValueHasNoProblems(t *testing.T) {
	for schema, value := range map[string]string{
		"Thing": `{"id":"6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b","name":"Acme","count":3,"ratio":0.5,"on":true,"kind":"customer",
			"at":"2026-11-08T10:00:00Z","note":null,"tags":["a"],"labels":{"x":"y"},"free":{"any":[1]},"closed":{"a":"b"}}`,
		"Member":   `{"user_id":"u1","role":"owner"}`,
		"Either":   `{"n":1}`,
		"Anything": `[1,"two",{}]`,
	} {
		if p := check(t, schema, value); len(p) != 0 {
			t.Errorf("%s: %v", schema, p)
		}
	}
	if p := check(t, "Either", `"text"`); len(p) != 0 {
		t.Errorf("either a string: %v", p)
	}
}

func TestEachDriftIsNamedByItsPath(t *testing.T) {
	for _, tc := range []struct{ schema, value, want string }{
		{"Thing", `{"name":"Acme"}`, `$: lacks the required field "id"`},
		{"Thing", `{"id":"nope","name":"Acme"}`, `$.id: a string that is not a UUID`},
		{"Thing", `{"id":"6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b","name":1}`, `$.name: want a string, got a number`},
		{"Thing", `{"id":"6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b","name":"A","count":1.5}`, `$.count: want an integer`},
		{"Thing", `{"id":"6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b","name":"A","kind":"partner"}`, `$.kind: a value outside the schema's enum`},
		{"Thing", `{"id":"6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b","name":"A","at":"yesterday"}`, `$.at: a string that is not a date-time`},
		{"Thing", `{"id":"6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b","name":null}`, `$.name: null, but the schema is not nullable`},
		{"Thing", `{"id":"6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b","name":"A","tags":[1]}`, `$.tags[0]: want a string`},
		{"Thing", `{"id":"6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b","name":"A","labels":{"x":2}}`, `$.labels.x: want a string`},
		{"Thing", `{"id":"6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b","name":"A","closed":{"b":"c"}}`, `$.closed: has the field "b", which the schema forbids`},
		{"Thing", `{"id":"6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b","name":"A","secret_field":"s3cret"}`, `$: has the field "secret_field", which the schema does not document`},
		{"Member", `{"role":"owner"}`, `$: lacks the required field "user_id"`},
		{"Member", `{"user_id":"u1","role":"owner","extra":true}`, `$: has the field "extra"`},
		{"Either", `true`, `$: matches none of the schema's oneOf/anyOf alternatives`},
		{"Thing", `[]`, `$: want an object, got an array`},
	} {
		p := check(t, tc.schema, tc.value)
		if !strings.Contains(strings.Join(p, "\n"), tc.want) {
			t.Errorf("%s %s: want %q in %v", tc.schema, tc.value, tc.want, p)
		}
	}
}

func TestProblemsNeverQuoteAValue(t *testing.T) {
	p := check(t, "Thing", `{"id":"s3cret-token","name":"A","kind":"s3cret-kind","secret_field":"s3cret-value"}`)
	if len(p) == 0 || strings.Contains(strings.Join(p, " "), "s3cret") {
		t.Fatalf("%v", p)
	}
}
