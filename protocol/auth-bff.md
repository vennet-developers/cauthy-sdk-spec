# The auth-bff protocol, version 1

A backend SDK serves these routes under one prefix (`/api/auth` by default). A client SDK talks only to them. The browser never holds a token: the session lives in an HttpOnly cookie the backend seals.

## Conventions

- Paths are relative to the prefix. The backend strips trailing slashes: `/session/` is `/session`. The bare prefix answers 404.
- `HEAD` behaves as `GET`. A method a route does not take answers `405` with `Allow`. There is no CORS: a client is same-origin.
- JSON in, JSON out, `content-type: application/json; charset=utf-8`, `cache-control: no-store` on every answer. A redirect answers `302` with `Location`.
- A route marked **auth** needs a signed-in session; without one it answers `401 unauthenticated`. It may set a renewed session cookie on the way out.
- A route marked **own** is an own-screens route: it needs the backend to know its tenant. A backend without a tenant answers `500 not_configured`.
- A route marked **step** reads a short-lived step cookie set by an earlier route; without it, `400 step_expired`.

## Levels

`basic` is the protocol as served today; `strict` adds three requirements. A backend declares which it meets. See the table at the end.

## Cookies

| Cookie | Holds | Max-Age |
| --- | --- | --- |
| `cauthy_session` (name configurable), written in chunks `cauthy_session.0`, `.1`… of 3500 characters | The sealed session | None for a browser session; `2592000` for a long one |
| `cauthy_session_flow` | Hosted sign-in state and PKCE verifier | 3600 |
| `cauthy_session_again` | One retry after a state mismatch | 120 |
| `cauthy_session_step` | The step between two own-screens calls (mfa, social, sso, code, link, upgrade: 600; passkey, enrol: 300) | 600 or 300 |

Every cookie: `Path=/; HttpOnly; SameSite=Lax`, and `Secure` when the application's origin is https. Clearing is `Max-Age=0`. A long session exists only when the person asked (`remember: true`) **and** Cauthy's token answer says the session is persistent; the backend never decides it alone.

## Errors

```json
{ "error": { "code": "invalid_email", "message": "…", "field": "email", "reasons": ["…"] } }
```

`field` names the body field at fault; `reasons` lists what a password lacks. Cauthy's own errors pass through with Cauthy's status and code. Cauthy unreachable is `503 unavailable`. Three answers are plain text: `404 Not found`, `405 Method not allowed`, and the hosted `/callback` failures.

| Code | Status | When |
| --- | --- | --- |
| `bad_request` | 400 | Body is not a JSON object, or a required shape is wrong |
| `required`, `invalid_email`, `too_long`, `weak_password` | 400 | Validation, with `field` |
| `step_expired` | 400 | The step cookie is missing or stale |
| `step_up_required` | 400 | The route needs the current password (`field: password`) |
| `invalid_token` | 422 | A reset, verify, magic-link or invitation token Cauthy does not know |
| `unauthenticated` | 401 | An **auth** route without a session |
| `cross_site` | 403 | The cross-site check failed |
| `not_configured` | 500 | An **own** route on a backend with no tenant |
| `unavailable` | 503 | Cauthy did not answer |

## Cross-site check

Every `POST` on an own-screens route, and `POST /me/organizations/check`, runs the check: when an `Origin` header is present it must equal the application's origin; when it is absent, `Sec-Fetch-Site` must be absent or `same-origin`. Otherwise `403 cross_site`. `Referer` is not read.

At `strict`, every mutation also carries the header `X-Cauthy-Request: 1`; without it the answer is `403 csrf_required`. The header cannot be set cross-site without CORS, so it is the double submit.

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

`GET /session` always answers `200 { "session": PublicSession | null, "status": "authenticated" | "unauthenticated" | "expired" }`.

## Routes

The table is `routes.yaml`; `openapi/auth-bff.yaml` is generated from it. Groups: `hosted`, `session`, `sign-in`, `me`, `organizations`, `other`. Three routes are deprecated from version 1 and will leave in version 2: `POST /sign-in/anonymous`, `POST /me/upgrade` and `GET /me/upgrade/social/{provider}`.

## Conformance

| Check group | Level | What it proves |
| --- | --- | --- |
| protocol | basic | 404 on unknown, trailing slash, HEAD as GET, 405 with Allow, no-store |
| session | basic | Sign in with a password, read the session, sign out; cookie attributes; long session only with `remember` and a tenant that allows it |
| errors | basic | Error shape; validation with `field`; 401 on auth routes |
| csrf | basic | `403 cross_site` on a foreign Origin and on `Sec-Fetch-Site: cross-site` |
| table | basic | Every route in the table answers its method with something other than 404 or 405; `/methods` and `/session` carry their fields |
| strict | strict | `Cauthy-Protocol: 1`; `X-Cauthy-Request` required; `next` on sign-in answers |
