# Reading a Pact contract

Pact is Vennet's contract network; `core-contracts` holds the manifests and links. This page says how an SDK reads the vendored graph (`contracts/graph.json`) and when it refuses to start. It documents the consumer's side; the schema belongs to core-contracts.

## What the SDK reads

| From the graph | Used for |
| --- | --- |
| The provider system `cauthy` and its `url` | The issuer: where tokens come from and where the API is |
| The consumer's `links` edge to `cauthy` that has a `sign_in` block | The sign-in client id (`sign_in.client_id`, else `pact.<link id>`), which is also the verifier's `client_id` (a person's token issued through another client is refused with `wrong_client`, rule R15 of [`verification/rules.md`](../verification/rules.md)), the tenant, the redirect URIs, `sign_in.require_system_proof`, `sign_in.persistent_sessions` |
| The link's `service` block | The confidential client `pact.<link id>.service` the application acts as, and its `jwks_url` |
| The consumer system's `jwks_url` | The path where the application publishes its own public key, when the `service` block names none |
| The consumer system's `events_url` | Where Cauthy sends events, when the system names one |

The tenant is the link's `identity.tenant` (an id), turned into a slug through the provider's `tenants` list.

### Link fields accepted for core-contracts (read by SDKs from protocol version 2)

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
6. With `CAUTHY_KEY`: any variable `key/cauthy-key.md` §10 refuses is set, or the key's issuer is not the graph's Cauthy `url` (`key_contract_issuer`). With the legacy root key: any of `CAUTHY_ISSUER`, `CAUTHY_CLIENT_ID`, `CAUTHY_CLIENT_SECRET`, `CAUTHY_SECRET`, `CAUTHY_SYSTEM`, `CAUTHY_TENANT`, `CAUTHY_SYSTEM_KEY`, `CAUTHY_SYSTEM_KEY_ID` is set. Two sources of the same thing are how an application signs people in through a client nobody meant. An option passed in code that the contract owns is refused the same way.
7. Neither `CAUTHY_KEY` nor `PACT_ROOT_KEY` is set, or `PACT_ROOT_KEY` is shorter than 32 characters.
8. Legacy root key only: a `service` block but no key store. With `CAUTHY_KEY` no key store is needed.
9. The `service` block names no `jwks_url` and neither does the system.
10. Legacy root key only: the key store keeps no key after writing one, or holds a key the root key cannot open (rotate with `PACT_ROOT_KEY_PREVIOUS`).

## Keys

- With `CAUTHY_KEY` the application's key is the Ed25519 key `key/cauthy-key.md` §5 derives. It is never stored and never rotates by itself: rotating it is a new `CAUTHY_KEY` (§9 there). It is published at `jwks_url` as `{"kty":"OKP","crv":"Ed25519","x":…,"kid":…,"alg":"EdDSA","use":"sig"}` with `Cache-Control: public, max-age=300`; during a rotation `CAUTHY_KEY_PREVIOUS`'s is published beside it. Cauthy accepts it only when it is also registered for the link's service client (registered in the dashboard, or adopted from the application's key client when the link was applied).
- With the legacy `PACT_ROOT_KEY`, the application's key is RS256 (2048 bits), made on first use, sealed at rest with a key derived from `PACT_ROOT_KEY`, kept in the key store, and published at `jwks_url` with `Cache-Control: public, max-age=300`.
- Derived keys use HKDF-SHA-256 with an empty salt and the label as `info`: `pact/seal/v1` seals the application's private key, `pact/cookie/v1` encrypts the session cookie, `pact/flow/v1` encrypts what a sign-in carries between its steps.
- Rotating the legacy RS256 key publishes the new one at once and signs with it after six minutes (the cache time plus a minute); the old key stays published 24 hours.
- Rotating the legacy root key: set the new one as `PACT_ROOT_KEY` and the old one as `PACT_ROOT_KEY_PREVIOUS` for a deploy. Writes use the new root, reads try both.

## The system proof

The application proves itself to Cauthy in two steps.

1. It asks for its own token at `<issuer>/v1/oauth/token` with `grant_type=client_credentials` and a **client assertion** (`private_key_jwt`, RFC 7523) signed with its key: `alg` `EdDSA` with `CAUTHY_KEY` (or RS256 with the legacy key store), with `kid`; `iss` and `sub` both the service client id (`pact.<link id>.service`); `aud` the token endpoint; `jti`; `iat`; `exp` = `iat` + 2 minutes (Cauthy refuses more than 5, and a repeated `jti`).
2. Cauthy answers an access token for the system. It lives 10 minutes and is renewed shortly before it ends.

Every call the backend passes to Cauthy on behalf of a person carries that access token in `X-Cauthy-System-Token`. Cauthy accepts it when it is valid, of the same tenant, and belongs to the system that owns the client the call names. Without a valid proof Cauthy ignores the person's address the application passes on (`X-Cauthy-Client-IP`).

With the proof required, a code exchange for the link's sign-in client, and every sign-in the application's own screens make naming that client, is refused without it (`403 system_proof_required` in both cases).

## One path, and a contract on top

Every application runs on `CAUTHY_KEY` (`key/cauthy-key.md`). A contract adds
to it; it never asks for a second secret.

| | Without a contract | With a contract |
| --- | --- | --- |
| Secret | `CAUTHY_KEY` | `CAUTHY_KEY` |
| Who the application is | Asked of Cauthy (`GET /v1/connect/self`) | Read from the graph: issuer, tenant, `pact.<link>`, `pact.<link>.service` |
| Client the key authenticates | the client named in the key | the link's service client |
| Sign-in client | the key's client | `pact.<link>` |
| System proof | sent, not required | sent; required as `system_proof` says |
| Published keys | none | the key's public half at `jwks_url` (`alg` `EdDSA`) |
| Drift | — | `GET /v1/pact/status`, including `keys` |

The route set an SDK serves is the same in both; with a contract it adds
`GET <jwks path>`.

### Legacy (1.x only)

`PACT_ROOT_KEY` (+ `PACT_ROOT_KEY_PREVIOUS`) with an RS256 key kept in a key
store, and the variables mode (`CAUTHY_*`), keep working in 1.x with one
deprecation warning per process and leave in 2.0.
