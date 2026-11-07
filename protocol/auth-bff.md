# The auth-bff protocol, version 1

A backend SDK serves these routes under one prefix (`/api/auth` by default). A client SDK talks only to them. The browser never holds a token: the session lives in an HttpOnly cookie the backend seals.

## Conventions

- Paths are relative to the prefix. The backend strips trailing slashes: `/session/` is `/session`. The bare prefix answers 404.
- `HEAD` behaves as `GET`. Any method other than `POST` on a route that only takes `POST` answers `405` with `Allow: POST`. Other mismatched methods are unspecified at `basic`; the runner only checks the first rule. There is no CORS: a client is same-origin.
- `cache-control: no-store` on every answer; JSON answers carry `content-type: application/json; charset=utf-8`, except `GET /sign-in/mfa/push/events`, which streams `text/event-stream` (marked `stream: true` in the table). A redirect answers `302` with `Location`.
- Query parameters are `snake_case` (`return_to`); JSON bodies and answers are `camelCase` (`newPassword`). The reads `GET /me/organizations/members` and `/roles` take the organization as the query parameter `id`; every mutation takes `organizationId` in the body.
- A route whose `needs` has **`session`** needs a signed-in session; without one it answers `401 unauthenticated`. It may set a renewed session cookie on the way out.
- A route whose `needs` has **`tenant`** is an own-screens route: it needs the backend to know its tenant. A backend without a tenant answers `500 not_configured`.
- A route whose `needs` has **`step`** reads a short-lived step cookie set by an earlier route; without it, `400 step_expired`.
- A route whose `needs` has **`crosssite`** runs the cross-site check; a route with **`json`** needs a JSON object body, else `400 bad_request`.
- A route marked `failures: redirect` is a browser redirect. A failure sends the browser to its return path with `?auth_error=<code>` appended (`&` when the path already has a query). The return path is the `return_to` query parameter on a route that starts a flow and the step cookie's saved path on a callback; it must be a path on this site (it starts with `/`, not `//`), otherwise it is the backend's configured after-sign-in path (default `/`). Two failures are not redirects: `500 not_configured` (JSON) on a backend without a tenant, and a plain-text `404` for an unknown provider.

## Levels

`basic` is the protocol as served today; `strict` adds three requirements. A backend declares which it meets. See the table at the end.

## Cookies

| Cookie | Holds | Max-Age |
| --- | --- | --- |
| `cauthy_session` (name configurable), always written in parts `cauthy_session.0`, `.1`… of at most 3500 characters, even when one part is enough | The sealed session | None for a browser session; `2592000` for a long one |
| `cauthy_session_flow` | Hosted sign-in state and PKCE verifier | 3600 |
| `cauthy_session_again` | One retry after a state mismatch | 120 |
| `cauthy_session_step` | The step between two own-screens calls (mfa, social, sso, code, link, upgrade: 600; passkey, enrol: 300) | 600 or 300 |

Every cookie: `Path=/; HttpOnly; SameSite=Lax`, and `Secure` when the application's origin is https. Clearing is `Max-Age=0`. A reader joins the parts in order from `.0` until the first missing index; there is no maximum count. A shorter new value deletes the parts the old one left behind. A long session exists only when the person asked (`remember: true`) **and** Cauthy's token answer says the session is persistent; the backend never decides it alone.

## Errors

```json
{ "error": { "code": "invalid_email", "message": "…", "field": "email", "reasons": ["…"] } }
```

`field` names the body field at fault; `reasons` lists what a password lacks. Cauthy's own errors pass through with Cauthy's status and code. Cauthy unreachable is `503 unavailable`; a token answer the backend cannot use is `502 unavailable`. Four answers are plain text: `404 Not found`, `405 Method not allowed`, the hosted `/callback` failures (`400`) and the hosted `/refresh` failure (`503`).

| Code | Status | When |
| --- | --- | --- |
| `bad_request` | 400 | Body is not a JSON object, or a required shape is wrong |
| `required`, `invalid_email`, `too_long`, `weak_password` | 400 | Validation, with `field` |
| `step_expired` | 400 | The step cookie is missing or stale |
| `step_up_required` | 401 | The route needs the current password (`field: password`); Cauthy's status passes through |
| `invalid_credentials` | 401 | A wrong email or password |
| `invalid_token` | 422 | A reset, verify, magic-link or invitation token Cauthy does not know |
| `unauthenticated` | 401 | A route with `session` in `needs`, without a session |
| `cross_site` | 403 | The cross-site check failed |
| `not_configured` | 500 | A route with `tenant` in `needs`, on a backend with no tenant |
| `csrf_required` | 403 | At `strict`, a mutation without `X-Cauthy-Request: 1` |
| `unavailable` | 503 | Cauthy did not answer |
| `unavailable` | 502 | Cauthy answered with a token the backend cannot use |
| `validation_error` | 400 | Cauthy refused a field (a phone number, an address) |
| `email_unchanged` | 400 | The new address is the current one (`field: email`) |
| `email_taken` | 409 | The address belongs to another account |
| `member_exists` | 409 | The person is already a member of the organization |
| `invalid_organization`, `invalid_member`, `invalid_role` | 400 | The organization, member or role is missing or malformed |
| `invalid_agent`, `invalid_passkey`, `invalid_provider` | 400 | The agent, passkey or provider to act on is missing or malformed |
| `passkey_failed` | 400 | A passkey ceremony Cauthy refused; Cauthy's status passes through |

The code set is open: a client handles an unknown code by its status.

## Cross-site check

Every `POST` on a route with `crosssite` in `needs` runs the check (all own-screens routes, `POST /sign-out` and `POST /me/organizations/check`; `POST /logout` is exempt): when an `Origin` header is present it must equal the application's origin (or the origin of the request's own URL, behind a proxy that rewrites the host); when it is absent, `Sec-Fetch-Site` must be absent or `same-origin`. Otherwise `403 cross_site`. `Referer` is not read.

At `strict`, every mutation (every `POST`) also carries the header `X-Cauthy-Request: 1`; without it the answer is `403 csrf_required`. The header cannot be set cross-site without CORS, so it works as a custom-header CSRF defense.

## Headers

At `strict`, every answer carries `Cauthy-Protocol: 1`. A client compares it with the version it was built for and warns on a mismatch.

## Sign-in answers

An own-screens sign-in route answers one of:

| `status` | Also carries | Meaning |
| --- | --- | --- |
| `signed_in` | `session` (a PublicSession) | Done; the session cookie is set |
| `mfa_required` | `method?` | A second step; the step cookie is set |
| `verification_required` | `email` | Sign-up held until the address is confirmed |
| `sent` | `sentTo?`, `channel?` | A code, link or push went out |
| `started` | `options` or `clientId` + `nonce` | A passkey or Google One Tap ceremony began |

At `strict`, every such answer also carries `next`: `done`, `mfa`, `verify_email`, `code`, `passkey`, `redirect`.

## Other answers

Every other JSON answer carries `status` too. The values, by route:

| `status` | Routes |
| --- | --- |
| `saved` | `POST /me` |
| `changed` | `POST /me/password`, `POST /me/organizations/members/role`, `POST /reset-password` |
| `signed_out` | `POST /sign-out`, `POST /me/sessions/end` |
| `sent` | `POST /forgot-password`, `/sign-in/mfa/send`, `/sign-in/mfa/email`, `/sign-in/mfa/push` (with `number`), `/me/mfa/phone`, `/me/email`, `/me/organizations/members/invite`, magic-link and email-code requests |
| `verified` | `POST /verify-email` |
| `accepted` | `POST /me/legal/accept` |
| `started` | `POST /me/mfa/setup`, passkey `begin` routes, Google One Tap `begin` |
| `enabled` | `POST /me/mfa/verify`, `POST /me/mfa/phone/verify` |
| `disabled` | `POST /me/mfa/disable` |
| `removed` | `POST /me/mfa/phone/remove`, `/me/passkeys/remove`, `/me/organizations/members/remove` |
| `renewed` | `POST /me/mfa/recovery-codes` |
| `added` | `POST /me/passkeys/add/finish`, `/me/organizations/members/add` |
| `unlinked` | `POST /me/identities/unlink` |
| `renamed`, `archived`, `deleted` | `POST /me/organizations/rename`, `/archive`, `/delete` |
| `decided` | `POST /me/organizations/check` |
| `ok` | `POST /sign-in/mfa/methods`, `GET /invitation` |
| `found`, `none` | `POST /sign-in/sso/discover` |
| `disconnected` | `POST /me/agents/disconnect` |

`GET /session` answers `authenticated`, `unauthenticated` or `expired`. In `mfa_required`, `method` is `email` when the code was just mailed, and absent otherwise. A phone `channel` is `sms` or `whatsapp`.

## PublicSession

```json
{
  "user": { "id": "…", "email": "…", "name": "…", "emailVerified": true, "restricted": false, "emailVerifyBy": "…", "locale": "es", "isAnonymous": false },
  "tenantId": "…",
  "roles": ["member"],
  "organizations": [{ "id": "…", "system": "acme-crm", "name": "…", "kind": "customer", "role": "owner", "metadata": {}, "externalId": "…" }],
  "expiresAt": "2026-11-07T20:00:00Z"
}
```

`restricted` is true when the account ran out of time to confirm its address: it may read and must refuse writes. `emailVerifyBy` (UTC) is when an unconfirmed address stops being enough; it is absent when there is no deadline. `locale`, `isAnonymous`, `emailVerifyBy` and an organization's `externalId` may be absent; `PublicSession` itself is `null` in `GET /session` when nobody is signed in, and every other field is always present.

`GET /session` always answers `200 { "session": PublicSession | null, "status": "authenticated" | "unauthenticated" | "expired" }`.

## The route table

`routes.yaml` has `version`, `prefix` and `routes`. Each route is one entry, one per line (continuation lines are indented). Keys:

| Key | Meaning |
| --- | --- |
| `id` | Stable name, `group.name`. Never reused |
| `method`, `path` | HTTP method and path relative to the prefix; `{provider}` is one path segment |
| `group` | `hosted`, `session`, `sign-in`, `me`, `organizations` or `other` |
| `level` | `basic` or `strict`: the lowest level at which the route must exist |
| `needs` | What the route requires, each with its failure: `session` (`401 unauthenticated`), `tenant` (`500 not_configured`), `step` (`400 step_expired`), `crosssite` (`403 cross_site`), `json` (`400 bad_request`) |
| `query`, `body` | Parameters by name, each `{type, required?}`. Types: `string`, `number`, `email`, `uuid`, `boolean`, `object`, `array`. A field without `required: true` is optional |
| `success` | `{ status, fields }` for a JSON answer (`fields` maps name to type), or `{ redirect: true }` for a `302` |
| `sets`, `clears` | Cookies the answer writes or deletes: `session`, `flow`, `again`, `step` |
| `errors` | Only the codes specific to the route. Codes implied by `needs` (`unauthenticated`, `not_configured`, `step_expired`, `cross_site`, `bad_request`) and body validation (`required`, `invalid_email`, `too_long`) are implicit on every route that takes the field |
| `text` | `true`: failures answer in plain text |
| `stream` | `true`: the answer is `text/event-stream`, not JSON |
| `failures` | `redirect`: failures are redirects with `?auth_error=<code>` (see Conventions) |
| `deprecated` | `true`: leaves in version 2 |

A field typed `T?` may be absent or `null`; a field without `?` is always present and never null.

## Routes

The table is `routes.yaml`; `openapi/auth-bff.yaml` is generated from it. Groups: `hosted`, `session`, `sign-in`, `me`, `organizations`, `other`. Three routes are deprecated in version 1 and removed in version 2: `POST /sign-in/anonymous`, `POST /me/upgrade` and `GET /me/upgrade/social/{provider}`.

## Conformance

| Check group | Level | What it proves |
| --- | --- | --- |
| protocol | basic | 404 on unknown, trailing slash, HEAD as GET, 405 with Allow, no-store |
| session | basic | Sign in with a password, read the session, sign out; cookie attributes; long session only with `remember` and a tenant that allows it |
| errors | basic | Error shape; validation with `field`; 401 on auth routes |
| csrf | basic | `403 cross_site` on a foreign Origin and on `Sec-Fetch-Site: cross-site` |
| table | basic | Every route in the table answers its method with something other than 404 or 405; `/methods` and `/session` carry their fields |
| strict | strict | `Cauthy-Protocol: 1`; `X-Cauthy-Request` required; `next` on sign-in answers |
