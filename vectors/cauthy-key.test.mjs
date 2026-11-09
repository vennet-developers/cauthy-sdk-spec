// Every valid vector, recomputed with WebCrypto only (Node >= 20). If this
// passes, a browser can make and read CAUTHY_KEY exactly as the Go reference.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const { subtle } = globalThis.crypto
const enc = new TextEncoder()
const b64u = b => Buffer.from(b).toString('base64url')
const PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])
const vectors = JSON.parse(readFileSync(new URL('./cauthy-key.json', import.meta.url)))

async function hkdf(secret, label) {
  const ikm = await subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(label) }, ikm, 256))
}

test('checksums and fields', async () => {
  for (const v of vectors.valid) {
    const key = v.key.trim()
    const parts = key.split('.')
    assert.equal(parts.length, 5, v.name)
    const sum = new Uint8Array(await subtle.digest('SHA-256', enc.encode(parts.slice(0, 4).join('.')))).slice(0, 6)
    assert.equal(b64u(sum), parts[4], v.name)
    assert.equal(Buffer.from(parts[1], 'base64url').toString(), v.issuer, v.name)
    assert.equal(Buffer.from(parts[2], 'base64url').toString(), v.client_id, v.name)
  }
})

test('derived keys, public key, kid and assertion', async () => {
  for (const v of vectors.valid) {
    for (const [label, hex] of Object.entries(v.derived)) {
      assert.equal(Buffer.from(await hkdf(v.secret, label)).toString('hex'), hex, `${v.name} ${label}`)
    }
    const seed = await hkdf(v.secret, 'cauthy/sign/v1')
    const priv = await subtle.importKey('pkcs8', new Uint8Array([...PKCS8, ...seed]), { name: 'Ed25519' }, true, ['sign'])
    const { x } = await subtle.exportKey('jwk', priv)
    assert.equal(x, v.public_jwk.x, v.name)
    const kid = b64u(new Uint8Array(await subtle.digest('SHA-256', enc.encode(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`))))
    assert.equal(kid, v.kid, v.name)
    const a = v.assertion
    const header = { alg: 'EdDSA', kid }
    const claims = { iss: v.client_id, sub: v.client_id, aud: a.token_endpoint, jti: a.jti, iat: a.iat, exp: a.iat + 120 }
    const si = `${b64u(enc.encode(JSON.stringify(header)))}.${b64u(enc.encode(JSON.stringify(claims)))}`
    const sig = new Uint8Array(await subtle.sign({ name: 'Ed25519' }, priv, enc.encode(si)))
    assert.equal(`${si}.${b64u(sig)}`, a.jws, v.name)
  }
})

// Rule 5 is "written exactly as a WHATWG URL serializes its origin": every
// valid issuer is its own origin, and every issuer refused with key_issuer
// either is not or is plain http to a remote host.
test('issuers are WHATWG origins', () => {
  for (const v of vectors.valid) {
    assert.equal(new URL(v.issuer).origin, v.issuer, v.name)
  }
  const local = new Set(['localhost', '127.0.0.1', '[::1]'])
  for (const v of vectors.invalid.filter(v => v.reason === 'key_issuer')) {
    const issuer = Buffer.from(v.key.split('.')[1], 'base64url').toString()
    let origin = null
    let url = null
    try {
      url = new URL(issuer)
      origin = url.origin
    } catch {}
    const remoteHTTP = url !== null && url.protocol === 'http:' && !local.has(url.hostname)
    assert.ok(origin !== issuer || remoteHTTP, `${v.name}: ${issuer} is a WHATWG origin`)
  }
})
