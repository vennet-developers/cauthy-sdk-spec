// Runs every vector in tokens.json against a Node SDK's verifyToken.
//
//   CAUTHY_AUTH_DIR=<path to the cauthy-auth package> node --test vectors/verify.test.mjs
//
// The package must be built (dist/). The SDK's own jose verifies the test
// keys, so nothing is installed here. A verdict that differs from the vector
// is a finding: it is printed and, with VECTORS_REPORT=<file>, written as
// JSON. It fails the run only with VECTORS_STRICT=1, which an SDK sets once
// it claims to meet verification/rules.md. cauthy-auth 0.x does not.
//
// The verdict is always compared. The reason is compared too when the SDK's
// error exposes one: a `reason` property equal to one of the codes in
// tokens.json. cauthy-auth 0.x carries no such code (its `reason` is jose's
// text), so there the expected reason is shown beside its message.
//
// Only the SDK's own refusal counts as "invalid": an error whose name is
// CauthyTokenError, or that carries a string `reason`. Any other error (a
// TypeError from an option the SDK does not accept, say) is "error", which
// is a finding of its own, never a pass.
//
// A case's allow_anonymous and allow_client_tokens (and allow_system, if a case
// ever sets it) are passed as allowAnonymous / allowClientTokens / allowSystem;
// an SDK that has no such option ignores them.
//
// A case with an `issuers` list is run with issuer: [issuer, ...issuers], the
// form jose takes for several accepted issuers. A finding on such a case reads
// "SDK accepts no issuers list" when the SDK errors on it; the list is for an
// SDK that takes a list of issuers.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(readFileSync(join(here, 'tokens.json'), 'utf8'))
const jwks = JSON.parse(readFileSync(join(here, 'jwks.json'), 'utf8'))
const dir = process.env.CAUTHY_AUTH_DIR
const isRefusal = (err) => err?.name === 'CauthyTokenError' || typeof err?.reason === 'string'
const codes = new Set(vectors.cases.map((c) => c.reason).filter(Boolean))

// How the findings that let a system's or a guest's token pass as a person are
// being closed (decision of 2026-11-07): in cauthy-auth 0.43, because apps in
// production run 0.42, and in @cauthyhq/node 1.0. Recorded in the report.
const RESOLUTIONS = {
  'cauthy-auth': Object.fromEntries(
    ['system/system-token', 'system/sys-empty', 'system/sys-null', 'system/sys-false', 'anonymous/guest'].map((name) => [name, 'fixed in cauthy-auth 0.43 and in @cauthyhq/node 1.0']),
  ),
}

// The SDK reads these as defaults; a stray one would change the verdicts.
for (const name of ['CAUTHY_ISSUER', 'CAUTHY_AUDIENCE', 'CAUTHY_TENANT_ID']) delete process.env[name]

test('vectors against cauthy-auth verifyToken', { skip: dir ? false : 'set CAUTHY_AUTH_DIR to the cauthy-auth package' }, async (t) => {
  const root = resolve(dir)
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  const require = createRequire(join(root, 'package.json'))
  const { createLocalJWKSet } = require('jose')
  const { verifyToken } = await import(pathToFileURL(join(root, pkg.exports['.'].import)).href)
  const keys = createLocalJWKSet(jwks)

  const findings = []
  for (const c of vectors.cases) {
    let got = 'valid'
    let gotReason = null
    let detail = ''
    try {
      await verifyToken(c.token, {
        issuer: c.config.issuers?.length ? [c.config.issuer, ...c.config.issuers] : c.config.issuer,
        allowAnonymous: c.config.allow_anonymous === true,
        allowClientTokens: c.config.allow_client_tokens === true,
        ...(c.config.allow_system === undefined ? {} : { allowSystem: c.config.allow_system === true }),
        audience: c.config.audience,
        tenantId: c.config.tenant,
        jwks: keys,
        now: new Date(c.now * 1000),
      })
    } catch (err) {
      got = isRefusal(err) ? 'invalid' : 'error'
      detail = err instanceof Error ? err.message : String(err)
      if (got === 'error' && c.config.issuers?.length) detail = `SDK accepts no issuers list (${detail})`
      gotReason = got === 'invalid' && codes.has(err?.reason) ? err.reason : null
    }
    const reasonDiffers = got === 'invalid' && c.expect === 'invalid' && gotReason !== null && gotReason !== c.reason
    if (got !== c.expect || reasonDiffers) {
      findings.push({ name: c.name, rule: c.rule, expect: c.expect, reason: c.reason ?? null, got, ...(gotReason ? { got_reason: gotReason } : {}), detail, ...(RESOLUTIONS[pkg.name]?.[c.name] ? { resolution: RESOLUTIONS[pkg.name][c.name] } : {}) })
      t.diagnostic(`FINDING ${c.name} (${c.rule}): want ${c.expect}${c.reason ? ` (${c.reason})` : ''}, got ${got}${gotReason ? ` (${gotReason})` : ''}${detail ? `: ${detail}` : ''}`)
    }
  }
  t.diagnostic(`${pkg.name} ${pkg.version}: ${vectors.cases.length - findings.length} of ${vectors.cases.length} vectors agree, ${findings.length} findings`)

  if (process.env.VECTORS_REPORT) {
    const report = { sdk: pkg.name, version: pkg.version, vectors: vectors.cases.length, findings }
    writeFileSync(process.env.VECTORS_REPORT, JSON.stringify(report, null, 2) + '\n')
  }
  assert.ok(vectors.cases.length > 0, 'tokens.json has no cases')
  if (process.env.VECTORS_STRICT === '1') {
    assert.deepEqual(findings.map((f) => f.name), [], 'every vector must agree')
  }
})
