package oas

import (
	"slices"
	"strings"
	"testing"
)

const fixture = `openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /v1/things/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: string}}
    get:
      operationId: getThing
      tags: [Things]
      responses:
        '200':
          description: one
          content:
            application/json:
              schema:
                type: object
                properties:
                  data: {$ref: '#/components/schemas/Thing'}
        '204': {description: none}
        '401': {$ref: '#/components/responses/Unauthorized'}
  /v1/things:
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/Thing'}
      responses:
        '201': {description: made}
components:
  responses:
    Unauthorized:
      description: no token
      content:
        application/json:
          schema: {$ref: '#/components/schemas/Thing'}
  schemas:
    Thing:
      type: object
      required: [name]
      properties:
        name: {type: string}
        id: {type: string, format: uuid}
        labels: {type: object, additionalProperties: {type: string}}
        free: {type: object, additionalProperties: true}
        closed: {type: object, additionalProperties: false}
    Alias:
      $ref: '#/components/schemas/Thing'
`

func load(t *testing.T, src string) *Doc {
	t.Helper()
	d, err := Load([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestLoadReadsOperationsByMethodAndPath(t *testing.T) {
	d := load(t, fixture)
	if got := d.Keys(); !slices.Equal(got, []string{"GET /v1/things/{id}", "POST /v1/things"}) {
		t.Fatalf("keys: %v", got)
	}
	op := d.Ops["GET /v1/things/{id}"]
	if op.Method != "GET" || op.Path != "/v1/things/{id}" || op.OperationID != "getThing" || op.Tags[0] != "Things" {
		t.Fatalf("op: %+v", op)
	}
	if len(op.Responses["204"].Content) != 0 || op.Responses["200"].Content["application/json"].Schema == nil {
		t.Fatalf("responses: %+v", op.Responses)
	}
	if r := op.Responses["401"]; r.Description != "no token" || r.Content["application/json"] == nil {
		t.Fatalf("a shared response is read in place of its $ref: %+v", r)
	}
}

func TestSchemasKeepPropertyOrderAndExtras(t *testing.T) {
	d := load(t, fixture)
	thing := d.Schemas["Thing"]
	if !slices.Equal(thing.PropertyOrder, []string{"name", "id", "labels", "free", "closed"}) {
		t.Fatalf("order: %v", thing.PropertyOrder)
	}
	if e := thing.Properties["labels"].AdditionalProperties; e == nil || !e.Allowed || e.Schema == nil || e.Schema.Type != "string" {
		t.Fatalf("labels: %+v", e)
	}
	if e := thing.Properties["free"].AdditionalProperties; e == nil || !e.Allowed || e.Schema != nil {
		t.Fatalf("free: %+v", e)
	}
	if e := thing.Properties["closed"].AdditionalProperties; e == nil || e.Allowed {
		t.Fatalf("closed: %+v", e)
	}
}

func TestResolveFollowsReferences(t *testing.T) {
	d := load(t, fixture)
	got, err := d.Resolve(d.Schemas["Alias"])
	if err != nil || got != d.Schemas["Thing"] {
		t.Fatalf("%v %v", got, err)
	}
	if name, ok := RefName("#/components/schemas/Thing"); !ok || name != "Thing" {
		t.Fatal(name)
	}
	if _, ok := RefName("#/components/parameters/TenantKey"); ok {
		t.Fatal("a parameter is not a schema")
	}
}

func TestLoadRefusesAResponseReferenceToNothing(t *testing.T) {
	bad := strings.Replace(fixture, "#/components/responses/Unauthorized", "#/components/responses/Nope", 1)
	if _, err := Load([]byte(bad)); err == nil || !strings.Contains(err.Error(), "Nope") {
		t.Fatalf("want an error naming Nope, got %v", err)
	}
}

func TestLoadRefusesAReferenceToNothing(t *testing.T) {
	bad := strings.Replace(fixture, "data: {$ref: '#/components/schemas/Thing'}", "data: {$ref: '#/components/schemas/Nope'}", 1)
	if _, err := Load([]byte(bad)); err == nil || !strings.Contains(err.Error(), "Nope") {
		t.Fatalf("want an error naming Nope, got %v", err)
	}
}
