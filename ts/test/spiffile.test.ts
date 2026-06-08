import assert from "node:assert/strict"
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

import {
  Identity,
  InvalidTokenError,
  SpiffeId,
  UnknownIdentityError,
  privateKeyFromPem,
  publicJwk,
  provision,
  unverifiedAudience,
} from "../src/index.js"

const TRUST_DOMAIN = "example.org"
const FIXTURES = JSON.parse(
  readFileSync(join(import.meta.dirname, "..", "..", "..", "conformance", "fixtures.json"), "utf8"),
)

function provisionedRoot(): string {
  const root = join(mkdtempSync(join(tmpdir(), "spiffile-")), "identity")
  provision.initRoot(root, TRUST_DOMAIN)
  provision.addService(root, "orders")
  provision.addService(root, "billing")
  return root
}

// -- cross-implementation fixtures --------------------------------------------

test("fixture JWK matches the python implementation", () => {
  const key = privateKeyFromPem(FIXTURES.orders_private_key_pem)
  assert.deepEqual(publicJwk(key), FIXTURES.orders_jwk)
})

test("fixture token minted by python verifies", () => {
  const dir = mkdtempSync(join(tmpdir(), "spiffile-fixture-"))
  writeFileSync(join(dir, "id"), "spiffe://example.org/billing\n")
  writeFileSync(join(dir, "key.pem"), FIXTURES.billing_private_key_pem)
  writeFileSync(join(dir, "bundle.json"), JSON.stringify(FIXTURES.bundle))

  const billing = Identity.fromFiles(join(dir, "id"), join(dir, "key.pem"), join(dir, "bundle.json"))
  const caller = billing.verify(FIXTURES.token_orders_to_billing_exp_2035)
  assert.equal(caller.id.toString(), "spiffe://example.org/orders")
})

test("fixture multi-audience token rejected", () => {
  // aud is an array containing the right audience — the profile requires a
  // single string, so every implementation must reject it.
  const dir = mkdtempSync(join(tmpdir(), "spiffile-fixture-"))
  writeFileSync(join(dir, "id"), "spiffe://example.org/billing\n")
  writeFileSync(join(dir, "key.pem"), FIXTURES.billing_private_key_pem)
  writeFileSync(join(dir, "bundle.json"), JSON.stringify(FIXTURES.bundle))

  const billing = Identity.fromFiles(join(dir, "id"), join(dir, "key.pem"), join(dir, "bundle.json"))
  assert.throws(
    () => billing.verify(FIXTURES.token_orders_to_billing_multi_aud_exp_2035),
    InvalidTokenError,
  )
})

test("fixture SPIFFE ID validation vectors", () => {
  for (const id of FIXTURES.invalid_spiffe_ids) {
    assert.throws(() => SpiffeId.parse(id), `must reject ${id}`)
  }
  for (const id of FIXTURES.valid_spiffe_ids) {
    assert.doesNotThrow(() => SpiffeId.parse(id), `must accept ${id}`)
  }
})

// -- behavioral parity with the other implementations --------------------------

test("roundtrip", () => {
  const root = provisionedRoot()
  const orders = provision.loadIdentity(root, "orders")
  const billing = provision.loadIdentity(root, "billing")

  const token = orders.token(billing.id)
  const caller = billing.verify(token)
  assert.equal(caller.id.toString(), `spiffe://${TRUST_DOMAIN}/orders`)
})

test("wrong audience rejected", () => {
  const root = provisionedRoot()
  const orders = provision.loadIdentity(root, "orders")
  const billing = provision.loadIdentity(root, "billing")

  const token = orders.token(`spiffe://${TRUST_DOMAIN}/someone-else`)
  assert.throws(() => billing.verify(token), InvalidTokenError)
})

test("unverifiedAudience reads aud without verifying", () => {
  const root = provisionedRoot()
  const orders = provision.loadIdentity(root, "orders")
  const billing = provision.loadIdentity(root, "billing")

  const token = orders.token(billing.id)
  assert.equal(unverifiedAudience(token), billing.id.toString())

  // malformed input is rejected
  assert.throws(() => unverifiedAudience("not.a.jwt"), InvalidTokenError)

  // an array aud is rejected, not silently coerced
  assert.throws(
    () => unverifiedAudience(FIXTURES.token_orders_to_billing_multi_aud_exp_2035),
    InvalidTokenError,
  )

  // a token with no aud returns null (signature is not checked, so a dummy sig is fine)
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" })).toString("base64url")
  const payload = Buffer.from(JSON.stringify({ sub: orders.id.toString(), exp: 9999999999 })).toString("base64url")
  assert.equal(unverifiedAudience(`${header}.${payload}.AAAA`), null)
})

test("unknown caller rejected", () => {
  const otherRoot = join(mkdtempSync(join(tmpdir(), "spiffile-other-")), "identity")
  provision.initRoot(otherRoot, TRUST_DOMAIN)
  provision.addService(otherRoot, "intruder")
  const intruder = provision.loadIdentity(otherRoot, "intruder")

  const root = provisionedRoot()
  const billing = provision.loadIdentity(root, "billing")
  const token = intruder.token(billing.id)
  assert.throws(() => billing.verify(token), UnknownIdentityError)
})

test("impersonation rejected — orders' key must not validate sub=billing", () => {
  const root = provisionedRoot()
  const billing = provision.loadIdentity(root, "billing")

  // Forge: an Identity claiming to be billing but holding orders' key file.
  const forged = Identity.fromFiles(
    join(root, "services", "billing", "id"),
    join(root, "services", "orders", "key.pem"),
    join(root, "bundle.json"),
  )
  const token = forged.token(billing.id)
  assert.throws(() => billing.verify(token), InvalidTokenError)
})

test("expired token rejected", () => {
  const root = provisionedRoot()
  const orders = provision.loadIdentity(root, "orders")
  const billing = provision.loadIdentity(root, "billing")

  const token = orders.token(billing.id, -120) // expired two minutes ago
  assert.throws(() => billing.verify(token), InvalidTokenError)
})

test("signing key hot-reloads after rotation", () => {
  const root = provisionedRoot()
  const billing = provision.loadIdentity(root, "billing")
  const orders = provision.loadIdentity(root, "orders") // loaded BEFORE rotation

  provision.rotateService(root, "orders", false)

  const token = orders.token(billing.id) // same Identity object
  assert.equal(billing.verify(token).id.toString(), orders.id.toString())
})

test("rotation with overlap keeps old-key tokens valid; without revokes", () => {
  const root = provisionedRoot()
  const billing = provision.loadIdentity(root, "billing")
  const orders = provision.loadIdentity(root, "orders")
  const tokenOldKey = orders.token(billing.id)

  provision.rotateService(root, "orders", true)
  assert.equal(billing.verify(tokenOldKey).id.toString(), orders.id.toString())

  provision.rotateService(root, "orders", false)
  assert.throws(() => billing.verify(tokenOldKey), InvalidTokenError)
})

test("remove service revokes", () => {
  const root = provisionedRoot()
  const billing = provision.loadIdentity(root, "billing")
  const orders = provision.loadIdentity(root, "orders")
  const token = orders.token(billing.id)

  provision.removeService(root, "orders")
  assert.throws(() => billing.verify(token), UnknownIdentityError)
})

test("bundle skips invalid entries", () => {
  const root = provisionedRoot()
  const bundlePath = join(root, "bundle.json")
  const doc = JSON.parse(readFileSync(bundlePath, "utf8"))
  doc.identities["spiffe://example.org/bad~path"] = { keys: [{ kty: "EC" }] }
  doc.identities["spiffe://example.org/no-keys"] = { keys: [] }
  writeFileSync(bundlePath, JSON.stringify(doc))

  const orders = provision.loadIdentity(root, "orders")
  const billing = provision.loadIdentity(root, "billing")
  const token = orders.token(billing.id)
  assert.equal(billing.verify(token).id.toString(), orders.id.toString())
})

test("serviceEnv + fromEnv", () => {
  const root = provisionedRoot()
  const identity = Identity.fromEnv(provision.serviceEnv(root, "orders"))
  assert.equal(identity.id.toString(), `spiffe://${TRUST_DOMAIN}/orders`)
})
