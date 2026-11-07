# cauthy-sdk-spec

The specification behind every Cauthy SDK, and the suite that proves an SDK follows it.

| Piece | What it is |
| --- | --- |
| `VERSION` | The protocol version every package declares it meets |
| `protocol/auth-bff.md` | The `/api/auth/*` protocol a backend SDK serves and a client SDK consumes |
| `protocol/routes.yaml` | The route table: one entry per route, the source of truth |
| `openapi/auth-bff.yaml` | The same routes as OpenAPI 3.1, generated from the table (planned) |
| `identity/rules.md` | What a token guarantees and what an application must never assume (planned) |
| `contract/pact.md` | How an SDK reads a Pact contract and when it refuses to start (planned) |
| `conformance/` | The runner: point it at a backend and it says what passes (planned) |

## Run the conformance runner (planned)

    cd conformance && go build -o bin/cauthy-conformance ./cmd/cauthy-conformance
    CONFORMANCE_PASSWORD=… bin/cauthy-conformance \
      --target http://localhost:3999/api/auth --origin http://localhost:3999 \
      --email member@example.com --level basic

It needs a backend that serves the protocol and one password account in its tenant.
Exit code 0 when every check of the level passes.
