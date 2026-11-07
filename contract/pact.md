# Reading a Pact contract

Pact is Vennet's contract network; `core-contracts` holds the manifests and links. This page says how an SDK reads the vendored graph (`contracts/graph.json`) and when it refuses to start. It documents the consumer's side; the schema belongs to core-contracts.

## What the SDK reads

| From the graph | Used for |
| --- | --- |
| The provider system `cauthy` and its `url` | The issuer: where tokens come from and where the API is |
| The consumer's `links` edge to `cauthy` that has a `sign_in` block | The sign-in client id (`sign_in.client_id`, else `pact.<link id>`), the tenant, the redirect URIs, `sign_in.require_system_proof`, `sign_in.persistent_sessions` |
| The link's `service` block | The confidential client `pact.<link id>.service` the application acts as, and its `jwks_url` |
| The consumer system's `jwks_url` | The path where the application publishes its own public key, when the `service` block names none |
| The consumer system's `events_url` | Where Cauthy sends events, when the system names one |

The tenant is the link's `identity.tenant` (an id), turned into a slug through the provider's `tenants` list.

### Link fields accepted for core-contracts (not yet on its main; Cauthy and SDKs read them in a later version)

| Field | Meaning |
| --- | --- |
| `identity.tenant` by slug | The link names the tenant by its slug. `identity.tenant` still accepts a UUID besides a slug. The graph adds `tenant_id` when the slug is listed, or `create_tenant: true` when it is new and the provider is Cauthy. The nil UUID is refused |
| `sign_in.require_verified_email` | Always present in the graph; the application asks for verified emails |
| `sign_in.require_system_proof: auto` (the graph adds `system_proof: off \| auto \| required`) | Added beside the boolean, which stays. Under `auto` Cauthy turns the requirement on by itself after the first sign-in through this client that carried the proof, and records when; until then, and for readers that know only the boolean, `require_system_proof` stays `false` |

Until SDKs read these fields, an SDK needs the link to name its tenant by UUID; a slug-named link is refused at start (the SDK looks the id up in the provider's `tenants` list).

## When it refuses to start

The SDK stops with a named configuration error, before serving a request, when:

1. `contract.system` is not a valid system id, the graph is not a context graph, or it lacks the system or `cauthy`.
2. No link from this system to `cauthy` carries a `sign_in` block; or several do and none was named.
3. The graph does not list a slug for the tenant the link names.
4. The link names no redirect URI.
5. Cauthy's `url`, a `jwks_url` or an `events_url` is not `https://` (`http://` is accepted for `localhost` and `127.0.0.1`).
6. Any of these variables is set alongside a contract: `CAUTHY_ISSUER`, `CAUTHY_CLIENT_ID`, `CAUTHY_CLIENT_SECRET`, `CAUTHY_SECRET`, `CAUTHY_SYSTEM`, `CAUTHY_TENANT`, `CAUTHY_SYSTEM_KEY`, `CAUTHY_SYSTEM_KEY_ID`. Two sources of the same thing are how an application signs people in through a client nobody meant. An option passed in code that the contract owns is refused the same way.
7. `PACT_ROOT_KEY` is missing, or is shorter than 32 characters (32 random bytes in base64url are 43).
8. The link has a `service` block and the application passes no key store.
9. The `service` block names no `jwks_url` and neither does the system.
10. The key store keeps no key after writing one, or holds a key the root key cannot open (rotate with `PACT_ROOT_KEY_PREVIOUS`).

## Keys

- The application's key is RS256 (2048 bits), made on first use, sealed at rest with a key derived from `PACT_ROOT_KEY`, kept in the key store, and published at `jwks_url` with `Cache-Control: public, max-age=300`.
- Derived keys use HKDF-SHA-256 with an empty salt and the label as `info`: `pact/seal/v1` seals the application's private key, `pact/cookie/v1` encrypts the session cookie, `pact/flow/v1` encrypts what a sign-in carries between its steps.
- Rotating the application's key publishes the new one at once and signs with it after six minutes (the cache time plus a minute); the old key stays published 24 hours.
- Rotating the root key: set the new one as `PACT_ROOT_KEY` and the old one as `PACT_ROOT_KEY_PREVIOUS` for a deploy. Writes use the new root, reads try both.

## The system proof

The application proves itself to Cauthy in two steps.

1. It asks for its own token at `<issuer>/v1/oauth/token` with `grant_type=client_credentials` and a **client assertion** (`private_key_jwt`, RFC 7523) signed with its current key: `alg` RS256 with `kid`; `iss` and `sub` both the service client id (`pact.<link id>.service`); `aud` the token endpoint; `jti`; `iat`; `exp` = `iat` + 2 minutes (Cauthy refuses more than 5, and a repeated `jti`).
2. Cauthy answers an access token for the system. It lives 10 minutes and is renewed shortly before it ends.

Every call the backend passes to Cauthy on behalf of a person carries that access token in `X-Cauthy-System-Token`. Cauthy accepts it when it is valid, of the same tenant, and belongs to the system that owns the client the call names. Without a valid proof Cauthy ignores the person's address the application passes on (`X-Cauthy-Client-IP`).

With the proof required, a code exchange for the link's sign-in client, and every sign-in the application's own screens make naming that client, is refused without it (`403 system_proof_required` in both cases).

## Two modes, never both

| Mode | Source of truth | Secret |
| --- | --- | --- |
| Contract | `contracts/graph.json` + `contracts/VERSION`, committed | `PACT_ROOT_KEY` |
| Variables | `CAUTHY_*` in the environment | `CAUTHY_SECRET` (at least 32 characters), `CAUTHY_CLIENT_SECRET` |

The route set an SDK serves is the same in both modes; contract mode adds `GET <jwks path>`.
