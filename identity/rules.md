# Identity rules

What a Cauthy token guarantees, and what an application must never assume. Every SDK guide links here; the conformance suite enforces what it can.

## The identifier is `sub`

A person is `sub`, a UUID Cauthy never reuses. An application keys its own rows by `sub`. The email is a contact address: it changes, it can belong to someone else later, and two tenants may each hold the same address. Never look a person up by email inside the application, and never join on it.

## Roles in the token are tenant-wide

`roles` in an access token are the person's roles in the **tenant** (the workspace): `owner`, `admin`, `member`, `viewer`, or a role the workspace made. They say what the person is to the application as a whole, never to one customer of it. What a person may do inside one business, practice or team is an **organization** role, read through the organizations endpoint or the session's `organizations`. An application that gates a customer's data on token roles lets every member of the tenant through.

## Email verification

| Tenant setting | What a token means |
| --- | --- |
| `confirm_email: true`, `verify_grace_days: 0` | No token exists before the address is confirmed. A valid token is a verified email |
| `confirm_email: true`, `verify_grace_days: N` | A token may exist for N days (0 to 90) with an unconfirmed address; `userinfo` reports `restricted` past the deadline, and a restricted account reads and does not write |
| `confirm_email: false` | The address is never checked |

The session's `user.emailVerified` says which case a person is in, and `GET /v1/oauth/userinfo` answers `email_verified`, `email_verify_by` (UTC) and `restricted`. An application that needs a verified address requires the first setting, and says so in its guide.

**The access token carries `email_verified`, as it was when the token was issued.** Its claims are, among them, `sub`, `tid`, `roles`, `email` and `email_verified`. A token lives at most 15 minutes, so the claim can be that old; an application that must act on the address at once reads the session or `userinfo` instead. A token issued before Cauthy wrote the claim lacks it: read it as `false`.

## What a client never receives

- An access or refresh token: both stay in the backend. The browser holds a sealed, HttpOnly cookie.
- `CAUTHY_KEY`, or anything derived from it.
- Anything from a route outside `protocol/routes.yaml`.

## Settings an application should require

Tenant settings are read and changed with `GET` and `PUT /v1/settings/auth` (permission `settings:manage`), or in the dashboard's sign-in settings. A field left out of a `PUT` keeps its value.

| Need | Setting | Where |
| --- | --- | --- |
| A valid token means a verified email | `confirm_email: true`, `verify_grace_days: 0` | `PUT /v1/settings/auth` |
| Nobody self-registers | `allow_signup: false` | `PUT /v1/settings/auth` |
| People may choose "keep me signed in" | `persistent_sessions: true` (workspace-wide; a client no longer holds it, and `allow_persistent_sessions` on a client answers `400 persistent_sessions_moved`) | `PUT /v1/settings/auth` |

Two needs belong to the application, not to the workspace. They are switches on the client people sign in through (`sign_in_client_id` of `GET /v1/connect/self`), set on the application's card in Cauthy's dashboard or with `PATCH /v1/oauth/clients/{client_id}` (permission `oauth_clients:manage`):

| Need | Field | Notes |
| --- | --- | --- |
| Only the application's own server signs people in | `system_proof: off \| auto \| required` | Every sign-in through the client must carry the system's proof (`X-Cauthy-System-Token`), else `403 system_proof_required`. `auto` turns into `required` by itself after the first sign-in that carried the proof (`system_proof_required_at`). Needs an application on `CAUTHY_KEY` (`400 system_proof_needs_key`) |
| A verified email for this application | `require_verified_email: true` | No token is issued through the client to a person whose email is unconfirmed |

Cauthy enforces both; an SDK reads neither and needs no change or deploy when they change. See [`key/cauthy-key.md`](../key/cauthy-key.md) §8.
