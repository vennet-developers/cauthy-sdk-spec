# Test-only keys

**These keys are public on purpose. They sign the token vectors and nothing else.** Never configure them in a Cauthy deployment, an SDK or an application. Each file is a private RSA key as a JWK, and its `comment` says so.

| File | `kid` | Role in the vectors |
| --- | --- | --- |
| `test-only-a.jwk.json` | `test-only-a` | The current signing key |
| `test-only-b.jwk.json` | `test-only-b` | The previous key, still published during a rotation |
| `test-only-attacker.jwk.json` | `test-only-attacker` | A key the issuer never published for signing; `jwks.json` also lists it as `test-only-enc` with `use: enc` |
| `test-only-weak.jwk.json` | `test-only-weak` | 1024 bits: published, and refused |

They were made once, from `conformance/`, with `go run ./cmd/gen-vectors -make-keys ../vectors/keys`, which writes only the files that are missing. Replacing a key changes every token in `vectors/tokens.json`: regenerate the vectors and commit both together.
