# cauthy-sdk-spec

The specification behind every Cauthy SDK, and the suite that proves an SDK follows it.

| Piece | What it is |
| --- | --- |
| `VERSION` | The protocol version every package declares it meets |
| `protocol/auth-bff.md` | The `/api/auth/*` protocol a backend SDK serves and a client SDK consumes |
| `protocol/routes.yaml` | The route table: one entry per route, the source of truth |
| `openapi/auth-bff.yaml` | The same routes as OpenAPI 3.1, generated from the table |
| `openapi/cauthy.yaml` | Cauthy's public API, extracted from Cauthy and checked against it (`openapi/README.md`) |
| `openapi/probes.yaml` | The requests `cauthy-api-check` sends to prove a Cauthy matches `cauthy.yaml` |
| `go/cauthyapi` | Go types of `cauthy.yaml` (module `github.com/vennet-developers/cauthy-sdk-spec/go`, standard library only) |
| `packages/spec` | `@cauthyhq/spec`: TypeScript types of `cauthy.yaml` and `auth-bff.yaml` |
| `identity/rules.md` | What a token guarantees and what an application must never assume |
| `verification/rules.md` | What a backend checks on a Cauthy access token, and the closed list of reason codes |
| `vectors/` | Signed test tokens and the verdict every verifier must reach, generated from test-only keys |
| `contract/pact.md` | How an SDK reads a Pact contract and when it refuses to start |
| `key/cauthy-key.md` | `CAUTHY_KEY`: the one value an application needs; parsing, derivation, signing, identity (read by every SDK, the CLI and Cauthy's dashboard) |
| `conformance/` | The runner: point it at a backend and it says what passes |

## Run the conformance runner

    cd conformance && go build -o bin/cauthy-conformance ./cmd/cauthy-conformance
    CONFORMANCE_PASSWORD=… bin/cauthy-conformance \
      --target http://localhost:3999/api/auth --origin http://localhost:3999 \
      --email member@example.com --level basic

`--json report.json` also writes the report as JSON. `--jwks-path` names the JWKS path of a backend in contract mode. Build with the Go version in `conformance/go.mod`.

It needs a backend that serves the protocol and one test account in its tenant. The account must:

- sign in with a password (not only a social or passkey login);
- have MFA off, and a verified email (otherwise the session checks are skipped and the run is reported incomplete);
- not sit behind a captcha on sign-in.

A run signs in at most three times and signs those sessions out when it ends (best effort), so it leaves no open sessions.
A `429` from the backend or Cauthy fails the check that met it.
The password is read only from the `CONFORMANCE_PASSWORD` environment variable, never from a flag.

Exit codes: `0` every check of the level passed and none was skipped; `1` a check failed; `2` usage or configuration error; `3` nothing failed but a check at or below the level was skipped (not a certification). A check that does not apply to the backend (for example the persistent-session check for the setting the tenant does not have) is reported `n/a` and does not make a run incomplete.

## Dashboard switches (level `switches`)

With a Cauthy and a token of the tenant's admin, the runner also changes the tenant's sign-in
settings, as an admin would in the dashboard, and checks the backend follows with no restart:
sign-ups closed then opened, passwords off then on, sign-in links on then off, passkeys off,
address confirmation on then off, and the backend client's long sessions on then off. It puts
each setting back as it found it, and deletes the accounts it signed up.

    CONFORMANCE_PASSWORD=… CAUTHY_ADMIN_TOKEN=… bin/cauthy-conformance \
      --target http://localhost:3999/api/auth --origin http://localhost:3999 --email member@example.com \
      --level switches --cauthy http://localhost:8080 --tenant acme --client-id <the backend's client id>

- The token needs `settings:manage`, `oauth_clients:manage`, `users:manage` and `users:delete`.
  It is read from `CAUTHY_ADMIN_TOKEN` (another variable with `--admin-token-env`), never from a flag.
- Without `--cauthy` the switch checks skip, and a run at `basic` or `strict` is still complete;
  `--level switches` without `--cauthy` is a usage error. At `basic` or `strict` with `--cauthy`,
  a switch the backend does not follow is reported `advisory`.
- `--switch-wait` (default `10s`) is how long the backend has to follow a switch.
- A sign-in link is offered only by an application that names its sign-in page.
- A run with `--cauthy` signs in at most six times.
- Point it at a tenant made for testing: while it runs, the tenant's sign-in settings change.

## Run the token vectors

`verification/rules.md` says what a backend checks on a Cauthy access token; `vectors/tokens.json` holds signed tokens and the verdict every verifier must reach, against the keys in `vectors/jwks.json`.

Go, against the reference verifier (part of `go test ./...`):

    cd conformance && go test ./internal/verify -run TestVectors

Node, against a Node SDK's `verifyToken` (here `cauthy-auth` from npm; a local build works the same way, with `CAUTHY_AUTH_DIR` pointing at the package directory after its build):

    SDK="$(mktemp -d)"
    npm install --prefix "$SDK" --ignore-scripts cauthy-auth@0.42.0 jose@5.10.0
    CAUTHY_AUTH_DIR="$SDK/node_modules/cauthy-auth" node --test vectors/verify.test.mjs

Each vector whose verdict differs is printed as a `FINDING`. `VECTORS_REPORT=<file>` also writes the findings as JSON; `VECTORS_STRICT=1` makes them fail the run, for an SDK that claims to meet the rules. `conformance/reports/cauthy-auth-0.42.0.vectors.json` is the report for `cauthy-auth` 0.42.0, and CI checks it is current.

After changing a case or a rule, regenerate the vectors (the keys stay):

    cd conformance && go run ./cmd/gen-vectors ../vectors/keys ../vectors

The keys in `vectors/keys` are test-only and public on purpose; see `vectors/keys/README.md`.

## Check a Cauthy against its public API

`openapi/README.md` says how `cauthy.yaml` is made and how `cauthy-api-check` proves a running
Cauthy matches it.

## Release

| What | Tag | How |
| --- | --- | --- |
| The runner and the API check (Go module `conformance`) | `conformance/vX.Y.Z` | the tag is the release |
| The Go types (Go module `go`) | `go/vX.Y.Z` | the tag is the release |
| `@cauthyhq/spec` | `spec/vX.Y.Z` (= `packages/spec/package.json`'s version) | `release.yml`, approved in the `npm` environment, trusted publishing |

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE).
