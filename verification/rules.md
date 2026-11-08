# Token verification

What a backend checks before it believes a Cauthy access token. Every SDK that verifies tokens follows these rules, and the vectors in [`vectors/`](../vectors) prove it: each is a token signed with a test key and the verdict every verifier must reach. The reference verifier, `conformance/internal/verify`, is the executable form of this page; where they disagree, it is a bug in one of them, and the vectors decide.

## What Cauthy issues

An access token is a JWS in compact form, signed RS256.

| Part | What Cauthy writes |
| --- | --- |
| Header | `alg: RS256`, `kid` (always), `typ: JWT` |
| `iss` | Cauthy's issuer, as configured for the deployment, with no trailing slash; or, for a token issued on a workspace's custom domain, that domain's origin |
| `aud` | An array with one string: the deployment's audience. An AI agent's token carries the resource it was issued for instead |
| `sub` | The person's id, a lowercase UUID. On a system's own token, the id of the client the system signs in as |
| `tid` | The workspace's id, a lowercase UUID |
| `iat`, `exp` | Seconds since the epoch. A person's token lives 15 minutes by default; a system's own token, 10 |
| `nbf` | Never written. A verifier still honours it when present |
| `jti` | A UUID, by which Cauthy revokes the token on its side |
| `roles` | The person's role slugs in the workspace; may be empty or `null` |
| `email`, `email_verified` | The person's address, and whether Cauthy had verified it when the token was issued (a boolean); both absent on a guest's token. A token issued before Cauthy wrote `email_verified` lacks it: read it as `false` |
| `anon` | `true` on a guest's token |
| `sys`, `sys_import` | Present only on a system's own token |
| (none) | A machine-to-machine token, issued for a `client_credentials` grant, has `sub` = the client's id, the client's roles and no `email`, and is otherwise indistinguishable from a person's token today. Nothing in it says it is not a person. A later Cauthy version will mark it with a claim of its own; until then a backend that must tell the two apart keeps its own list of client ids. Rule R13 will refuse the mark when it exists, as it refuses `sys` |
| `auth_time`, `keep` | When the session began, and whether it is a long one |
| `custom`, `scope`, `client_id`, `act` | Present on some tokens; ignored by these rules |

The keys are published at `<issuer>/.well-known/jwks.json`: every active key as `kty: RSA`, `use: sig`, `alg: RS256`, with its `kid`, answered with `Cache-Control: public, max-age=3600`. During a rotation the set holds the previous key beside the current one, and tokens signed with either are valid.

## Configuration

| Setting | Rule |
| --- | --- |
| `issuer` | Required. `https://` (`http://` only for `localhost`, `127.0.0.1`, `*.localhost` and `*.test`), no trailing slash, no query or fragment. The JWKS URL, `<issuer>/.well-known/jwks.json`, is derived from it; it is never read from a token |
| `issuers` | Optional list of further issuers a token may name, each following the same format rules as `issuer`. A workspace with a custom domain lists the domain's origin here, because its tokens carry either Cauthy's issuer or the domain's, depending on where the person signed in. The keys always come from `issuer`'s set; no issuer in this list is ever fetched. Default: empty, so exactly one issuer is accepted |
| `audience` | Required |
| `tenant` | Required: the workspace id, a lowercase UUID, not the nil UUID. A verifier without a tenant does not start |
| `leeway` | Clock tolerance. Default 30 seconds when unset; 0 to 60 accepted, and an explicit 0 means none |
| `allow_anonymous` | Whether a guest's token is accepted. Default `false` |
| `allow_client_tokens` | Whether a client's own token (`token_use`, from a `client_credentials` grant) is accepted, for a backend that serves machines as well as people. Default `false` |
| `client_id` | Optional: the client the backend signs people in through. When set, a person's token issued through another client is refused (R15). In contract mode it is the link's sign-in client (see [`contract/pact.md`](../contract/pact.md)). Default: none, and `azp` is not checked |

A configuration that breaks a rule is an error when the verifier is built, before it verifies anything.

## Rules

The rules run in this order, and a token is refused at the first one it breaks, with that rule's reason. Claims are read only after the signature holds.

| Rule | Check | Reason when it fails |
| --- | --- | --- |
| R1 | The token is at most 8192 bytes. Checked before anything is decoded | `too_large` |
| R2 | Only the bytes `A-Z a-z 0-9 - _` and the two dots (so no line break, space or padding); three segments separated by `.`, each base64url without padding; the header a JSON object; no JSON object, in the header or the payload, repeats a name | `malformed` |
| R3 | The header's `alg` is exactly `RS256`. The algorithm is fixed by the verifier, never chosen by the token: `none`, `HS256` (including one keyed with the published public key), `RS384`, `RS512`, `PS256`, `ES256` and a missing `alg` are all refused | `alg_not_allowed` |
| R4 | No `crit` header. `jku`, `x5u`, `jwk` and `x5c` are never used to find a key. `typ` is not required, but when present it is the string `JWT` or `at+jwt`, in any case: another type, such as the `cauthy-webhook+jwt` of Cauthy's webhooks, is not an access token | `unsupported_header` |
| R5 | `kid` is a non-empty string, and the issuer's set has a usable key with that `kid`. A key is usable when `kty` is `RSA`, `use` is `sig` or absent, and `alg` is `RS256` or absent; a usable key under 2048 bits is refused on its own reason | `missing_kid`, `unknown_kid`, `weak_key` |
| R6 | The RSASSA-PKCS1-v1_5 SHA-256 signature verifies over the first two segments exactly as received | `bad_signature` |
| R7 | The payload is a JSON object (else `malformed`) and has `iss`, `sub`, `aud`, `exp`, `iat` and `tid` | `missing_claim` |
| R8 | `iss` is a string; `sub` and `tid` are lowercase UUIDs; `aud` is a string or a non-empty array in which every element is a string; `exp`, `iat` and `nbf` are JSON integers within ±2^53, written as integers (not strings, not fractions, and no exponent or decimal point: `1.8e9` and `1800000000.0` are refused); `roles` is an array in which every element is a string, or `null`; `email` is a string; `email_verified` and `anon` are booleans; `token_use` and `azp` are strings. None of them is `null` except `roles`, and no array element is `null`. Claims not named here are ignored, `sys` among them (R13 only looks for it) | `invalid_claim` |
| R9 | `iss` equals the configured `issuer` or one of the configured `issuers`, byte for byte: no trimming, no case folding | `wrong_issuer` |
| R10 | `aud` equals the configured audience, or, as an array, contains it | `wrong_audience` |
| R11 | With leeway L: refused when now ≥ `exp` + L; when `nbf` is present and now < `nbf` − L; when now < `iat` − L | `expired`, `not_yet_valid`, `issued_in_future` |
| R12 | `tid` equals the configured tenant | `wrong_tenant` |
| R13 | No `sys` claim, whatever its value, `null` and `false` included: its presence is the mark. A system's own token never stands for a person. Then no `token_use` claim, whatever its value, unless the backend allows client tokens (`allow_client_tokens`): a client's own token stands for a machine, not a person. A token with both is refused as a system's | `system_token`, `client_token` |
| R14 | `anon` is not `true`, unless the backend allows guests | `anonymous_token` |
| R15 | When the backend names its client (`client_id`) and the token carries `azp`, `azp` equals it, byte for byte. A token with no `azp` was issued with no client named, and passes | `wrong_client` |

## Keys and refetching

| Rule | Check |
| --- | --- |
| K1 | The JWKS is `<issuer>/.well-known/jwks.json`, fetched with GET, following no redirect, within 5 seconds; only a `200` of at most 64 KiB counts |
| K2 | The set is fetched on first use and again once older than the answer's `max-age`, capped at one hour (5 minutes when the answer names none) |
| K3 | A `kid` the set does not hold triggers a fetch only when the last fetch started at least the cooldown ago (default 30 seconds). Otherwise the token is refused at once with `unknown_kid`. A `kid` found unknown is never remembered as bad: after the cooldown, the next token that names it fetches again. So forged `kid`s cause at most one fetch per cooldown, and a key Cauthy has just started signing with is accepted at most one cooldown after its first token arrives |
| K4 | One fetch at a time: a token that needs the set while it is being fetched waits for that fetch |
| K5 | A failed fetch keeps the last good set |
| K6 | A set in which two usable keys share a `kid` is refused as a whole (K5 applies) |

## What a verified token does not tell

- **Revocation.** Cauthy revokes a token by its `jti` on its own side; a verifier that works offline cannot see that, and accepts the token until `exp`. A backend that must see a sign-out at once asks Cauthy instead.
- **Business roles.** `roles` are workspace-wide; see [`identity/rules.md`](../identity/rules.md).
- **A verified address, now.** `email_verified` is what Cauthy knew when it issued the token, up to 15 minutes ago; see [`identity/rules.md`](../identity/rules.md).
- **A machine.** A machine-to-machine token passes as a person's today; see the table above.

## Reason codes

The list is closed: a verifier reports one of these and no other, and the vectors use no other.

| Code | Rule | Meaning |
| --- | --- | --- |
| `too_large` | R1 | Longer than 8192 bytes |
| `malformed` | R2, R7 | Not three base64url segments, or the header or payload is not a JSON object |
| `alg_not_allowed` | R3 | `alg` is not `RS256` |
| `unsupported_header` | R4 | A `crit` header |
| `missing_kid` | R5 | No `kid`, or an empty one |
| `unknown_kid` | R5, K3 | No usable key with that `kid` in the issuer's set |
| `weak_key` | R5 | The key is under 2048 bits |
| `bad_signature` | R6 | The signature does not verify |
| `missing_claim` | R7 | A required claim is absent |
| `invalid_claim` | R8 | A claim has the wrong type or format |
| `wrong_issuer` | R9 | `iss` is neither the configured issuer nor one of the listed issuers |
| `wrong_audience` | R10 | `aud` does not hold the configured audience |
| `expired` | R11 | Past `exp` and the leeway |
| `not_yet_valid` | R11 | Before `nbf`, beyond the leeway |
| `issued_in_future` | R11 | `iat` ahead of now, beyond the leeway |
| `wrong_tenant` | R12 | `tid` is another workspace |
| `system_token` | R13 | A system's own token |
| `client_token` | R13 | A client's own token where client tokens are not allowed |
| `anonymous_token` | R14 | A guest's token where guests are not allowed |
| `wrong_client` | R15 | A person's token issued through another client than the one the backend names |

## Vectors

| File | What it is |
| --- | --- |
| `vectors/keys/*.jwk.json` | The test keys, as private JWKs. **Test only**: they are public on purpose and sign nothing real |
| `vectors/jwks.json` | The set a verifier loads: the current key, the previous key, a 1024-bit key, and a key published with `use: enc` |
| `vectors/tokens.json` | Every case: `name`, `rule`, `description`, `token`, `now` (seconds since the epoch), `config` (`issuer`, `audience`, `tenant`, and `issuers`, `allow_anonymous`, `allow_client_tokens` and `client_id` when set), `expect` (`valid` or `invalid`) and, for an invalid one, `reason` |

Every case is built to be accepted, or to be refused by one rule only, so the reason is the same whatever order a verifier runs its checks in. The vectors assume the default leeway (30 seconds) and the 8192-byte limit; a case at a boundary says so in its description.

Both files are generated, and the same keys always give the same bytes:

    cd conformance && go run ./cmd/gen-vectors ../vectors/keys ../vectors

A verifier passes when, for every case, it reaches the case's verdict and, for an invalid one, reports the case's reason (or, when it reports no reason codes yet, at least the verdict).
