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

**The access token does not carry `email_verified` today.** Its claims are `sub`, `tid`, `roles`, `email` and the registered ones. The `email_verified` claim arrives with stage 2 of the five-minute plan; until then an application reads it from the session or from `userinfo`, never from the token.

## What a client never receives

- An access or refresh token: both stay in the backend. The browser holds a sealed, HttpOnly cookie.
- The system key or the root key.
- Anything from a route outside `protocol/routes.yaml`.

## Settings an application should require

Tenant settings are read and changed with `GET` and `PUT /v1/settings/auth` (permission `settings:manage`), or in the dashboard's sign-in settings. A field left out of a `PUT` keeps its value.

| Need | Setting | Where |
| --- | --- | --- |
| A valid token means a verified email | `confirm_email: true`, `verify_grace_days: 0` | `PUT /v1/settings/auth` |
| Nobody self-registers | `allow_signup: false` | `PUT /v1/settings/auth` |

Two needs belong to the application's Pact link, not to a tenant setting:

| Need | Link field | Notes |
| --- | --- | --- |
| Only the system's own proof signs people in | `sign_in.system_proof: required` (`off`, `auto` or `required`) | `auto` leaves the choice to Cauthy (its exact rule is defined by Cauthy, not by this repository). The boolean `sign_in.require_system_proof` stays `false` under `auto`. Needs a `service` block |
| People may stay signed in | `sign_in.persistent_sessions: true` | The contract owns the switch: changing the client by hand answers `409 from_contract` |
| A verified email for this application | `sign_in.require_verified_email: true` | |

Everything in the table above except `persistent_sessions` and the boolean `require_system_proof` is new in stage 2 and is read by SDKs from then on; see [`contract/pact.md`](../contract/pact.md).
