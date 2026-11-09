# CAUTHY_KEY

Version 1 (`cauthy1`). Normative. The reference implementation is
`conformance/cauthykey`; the vectors are `vectors/cauthy-key.json`. An SDK
conforms when it passes every vector.

## 1. What it is

The one value an application needs to sign people in with Cauthy. It names
Cauthy (the issuer), the application's client, and holds a 32-byte secret.
Cauthy never sees the secret: the dashboard makes the key in the browser and
sends Cauthy only the public half of the signing key derived from it.

## 2. Grammar

    CAUTHY_KEY = "cauthy1" "." ISSUER "." CLIENT "." SECRET "." CHECK
    ISSUER     = b64u( utf8( origin ) )
    CLIENT     = b64u( utf8( client_id ) )
    SECRET     = b64u( 32 random bytes )          ; 43 characters
    CHECK      = b64u( SHA-256( ascii( "cauthy1." ISSUER "." CLIENT "." SECRET ) )[0:6] )   ; 8 characters

b64u is base64url (RFC 4648 §5) without padding, canonical: a decoder refuses
padding, characters outside the alphabet and non-zero unused bits.

## 3. Parsing, in this order

| # | Rule | Reason |
| --- | --- | --- |
| 1 | Trim ASCII space, tab, CR and LF at both ends. The rest must be printable ASCII and at most 512 characters | `key_format` |
| 2 | The text before the first `.` must be `cauthy1`. Another `cauthy<digits>` is a newer version | `key_version` |
| 3 | Exactly five `.`-separated parts, none empty | `key_format` |
| 4 | `CHECK` equals the recomputed one (constant-time compare) | `key_checksum` |
| 5 | `ISSUER` decodes to an ASCII origin: scheme `https`, or `http` with host `localhost`, `127.0.0.1` or `[::1]`; lowercase host; optional port, never the scheme's default (`:443`, `:80`); no userinfo, path (not even `/`), query or fragment. Written exactly as a WHATWG URL serializes its origin | `key_issuer` |
| 6 | `CLIENT` decodes to 1–128 bytes of `[A-Za-z0-9._-]` | `key_client` |
| 7 | `SECRET` is 43 characters and decodes to 32 bytes | `key_secret` |

A refusal names the reason and never the value.

## 4. Derived keys

HKDF-SHA-256 (RFC 5869), salt empty, input key material the UTF-8 bytes of the
`SECRET` segment **as text** (43 characters), output 32 bytes:

| info | Use |
| --- | --- |
| `pact/cookie/v1` | seals the session cookie (JWE `dir`, `A256GCM`) |
| `pact/flow/v1` | seals what a sign-in carries between its steps |
| `pact/seal/v1` | reserved; nothing is sealed with it in key mode |
| `cauthy/sign/v1` | the Ed25519 seed (RFC 8032 §5.1.5) |

The first three are the derivation of `contract/pact.md` with the `SECRET`
segment as the root key, so one routine serves both.

## 5. The signing key

Ed25519. Public JWK `{"kty":"OKP","crv":"Ed25519","x":<b64u 32 bytes>}`.
`kid` = b64u(SHA-256(`{"crv":"Ed25519","kty":"OKP","x":"<x>"}`)) (RFC 7638).
WebCrypto imports the seed as PKCS#8: the 16 bytes
`302e020100300506032b657004220420` followed by the seed.

## 6. The client assertion

`private_key_jwt` (RFC 7523) on every call to `<issuer>/v1/oauth/token` and
`<issuer>/v1/oauth/revoke`:

    header  {"alg":"EdDSA","kid":"<kid>"}
    claims  {"iss":"<client>","sub":"<client>","aud":"<issuer>/v1/oauth/token","jti":"<uuid v4>","iat":<now>,"exp":<now + 120>}

Serialized exactly in that member order, without spaces. Form fields:
`client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
`client_assertion`. A new `jti` per call. No `client_secret` is ever sent in
key mode.

## 7. Who the application is

Without a contract, the application asks once at start, and every 5 minutes
after with `If-None-Match`:

1. `POST <issuer>/v1/oauth/token` `grant_type=client_credentials` with the assertion → its access token.
2. `GET <issuer>/v1/connect/self` with `Authorization: Bearer <that token>` →
   `{data: {issuer, audience, tenant: {id, slug}, system, client_id,
   sign_in_client_id, app_urls[], callback_path, key: {kid, retires_at},
   contract}}`.

The same access token is the system proof (`X-Cauthy-System-Token`).

The redirect URI is `<origin><basePath>/callback` with `origin` the request's
origin when it is in `app_urls`; else the only entry when there is one; else
the request is refused `400 unknown_origin`.

When Cauthy is unreachable the backend starts and answers `503 unavailable` on
its auth routes until the identity arrives. When Cauthy refuses the key
(`invalid_client`) it answers `503 misconfigured` and logs the `kid` once.

## 8. With a contract

See `contract/pact.md`. The issuer must be the graph's Cauthy `url`
(`key_contract_issuer`). The key authenticates the link's service client and
the backend publishes the public key at the contract's `jwks_url`.

## 9. Rotation

`CAUTHY_KEY_PREVIOUS` is the key being replaced. It must name the same issuer
and client (`key_previous_mismatch`). Its cookie and flow keys are read, never
written; with a contract its public key is published too. Signing always uses
`CAUTHY_KEY`.

## 10. Variables refused beside it

`CAUTHY_ISSUER`, `CAUTHY_CLIENT_ID`, `CAUTHY_CLIENT_SECRET`, `CAUTHY_SYSTEM`,
`CAUTHY_TENANT`, `CAUTHY_SYSTEM_KEY`, `CAUTHY_SYSTEM_KEY_ID`, `CAUTHY_BASE_URL`,
`CAUTHY_AUDIENCE`, `CAUTHY_TENANT_ID`. `CAUTHY_SECRET` and `PACT_ROOT_KEY` are
accepted beside it only as read-only previous keys while an application moves
to `CAUTHY_KEY` (with one warning); in 2.0 they are refused too.
