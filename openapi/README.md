# openapi/

| File | What it is | Made by |
| --- | --- | --- |
| `auth-bff.yaml` | The `/api/auth/*` protocol a backend SDK serves | `conformance/cmd/gen-openapi` from `protocol/routes.yaml` |
| `cauthy.yaml` | Cauthy's public API: what an SDK may call | extracted from Cauthy's own document (see below); never edited here |
| `probes.yaml` | One request, at least, per operation of `cauthy.yaml`, and the answers that pass | by hand |
| `redocly.yaml` | The lint rules CI applies to `cauthy.yaml` | by hand |

## How `cauthy.yaml` is made

Cauthy documents every route it serves in its own OpenAPI document, and a test there keeps
that document equal to the router. A list in the Cauthy repository names the operations that
are public; Cauthy's `make openapi-public` cuts them out, with the schemas they reach, under
a public header, and writes this file. It refuses the families that never leave Cauthy (the
platform owner's, the deployment's admin key, Cauthy's own pages and dashboard) and any text
that names an internal route, a deployment secret or a real host.

An SDK calls only what this file lists (spec, section 7).

## How it is checked

- **Here, in CI:** Redocly lints the structure; `go test ./...` in `conformance/` proves every
  operation has a probe, every probe names an operation, and no probe reads a variable nothing
  set; the Go and TypeScript types are regenerated and must not change.
- **Against a running Cauthy:** `cauthy-api-check` sends every probe and checks each answer's
  status (expected by the probe *and* listed by the document), content type, and body against
  the schema. A field the schema does not document is drift. Cauthy's `make api-check` runs it
  against its local stack; anyone with a Cauthy can run it:

      cd conformance && go build -o bin/cauthy-api-check ./cmd/cauthy-api-check
      CAUTHY_API_CHECK_MEMBER_PASSWORD=… CAUTHY_API_CHECK_OWNER_PASSWORD=… CAUTHY_API_CHECK_CLIENT_SECRET=… \
        bin/cauthy-api-check --cauthy http://localhost:8080 --tenant acme \
        --var member_email=… --var owner_email=… --var system=… --var client_id=… --var origin=http://localhost:3999

  The inputs are listed at the top of `probes.yaml`. Secrets go in `CAUTHY_API_CHECK_<NAME>`,
  never in a flag. Exit code 0 every probe passed, 1 one failed, 2 setup.

## Not public yet

These families are served by Cauthy and documented there, but not published here. Each joins
`cauthy.yaml` when an SDK needs it, with its probes:

- People: reading, renaming, suspending a person; their sessions and tokens; importing accounts
- Personal access tokens (`/v1/auth/tokens`), sessions (`/v1/auth/session`, `/v1/auth/token/*`), workspaces of a person (`/v1/auth/tenants`)
- The second step's phone app (`/v1/auth/mfa/push/devices`, `/pending`, `/respond`), recovery (`/v1/auth/mfa/recover`), sign-in risk (`/v1/auth/risk/check`), choosing a workspace at sign-in (`/v1/auth/login/select`), social relay, third-party tokens, SSO callbacks and metadata
- Authorization: permission checks, policies, roles and assignments; ABAC; ReBAC; segments
- Systems: policy, catalog writes, sign-up modes; connecting a system (`/v1/connect`)
- OAuth clients: creating, rotating, deleting, setting a theme
- SSO connections and setup links; social providers; third-party issuers
- Webhook-like connectors; audit; risk reports; threat feeds; MFA policy
- GDPR (data, export, erasure), consent, legal documents, plan, sign-up of a workspace, onboarding
- SCIM 2.0 (a standard of its own; its own document)
- Health

These never will be: the platform owner's routes, the deployment's admin key routes, Cauthy's
hosted pages, and its dashboard's flows, assistant and notifications.
