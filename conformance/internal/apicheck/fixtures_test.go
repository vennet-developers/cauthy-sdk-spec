package apicheck

// The document and the probes the package's tests share: three operations
// on things, the first probe capturing the id the next two use.

const testDoc = `openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /v1/things:
    post:
      responses:
        '201':
          description: made
          content:
            application/json:
              schema:
                type: object
                properties:
                  data: {$ref: '#/components/schemas/Thing'}
        '400':
          description: refused
          content:
            application/json:
              schema: {$ref: '#/components/schemas/Problem'}
  /v1/things/{id}:
    get:
      responses:
        '200':
          description: one
          content:
            application/json:
              schema:
                type: object
                properties:
                  data: {$ref: '#/components/schemas/Thing'}
    delete:
      responses:
        '200': {description: gone}
        '204': {description: gone}
components:
  schemas:
    Thing:
      type: object
      required: [id, name]
      properties:
        id: {type: string}
        name: {type: string}
    Problem:
      type: object
      required: [errors]
      properties:
        errors: {type: array, items: {type: object}}
`

const testProbes = `version: 1
probes:
  - id: create
    op: POST /v1/things
    auth: token
    body: {name: "thing {run}"}
    expect: 201
    capture: {thing_id: data.id}
  - id: read
    op: GET /v1/things/{id}
    auth: token
    params: {id: "{thing_id}"}
    expect: 200
  - id: remove
    op: DELETE /v1/things/{id}
    auth: token
    params: {id: "{thing_id}"}
    expect: [200, 204, 404]
`
