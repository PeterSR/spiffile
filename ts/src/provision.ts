/**
 * Provisioning primitives: create, rotate and revoke identities.
 *
 * Building blocks for producers — provisioning scripts, development tooling,
 * operators. They generate keypairs and maintain the trust bundle; consumers
 * only ever read the resulting files via {@link Identity}.
 *
 * A provisioned root directory looks like:
 *
 *     <root>/
 *       bundle.json                # the trust bundle (distribute to everyone)
 *       services/<name>/id         # the service's SPIFFE ID
 *       services/<name>/key.pem    # the service's private key (deliver only to it)
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { join } from "node:path"

import { Bundle, BUNDLE_VERSION, type BundleDocument } from "./bundle.js"
import { SpiffileError } from "./errors.js"
import {
  DIR_BUNDLE_FILENAME,
  DIR_ID_FILENAME,
  DIR_KEY_FILENAME,
  ENV_BUNDLE_FILE,
  ENV_ID_FILE,
  ENV_KEY_FILE,
  Identity,
} from "./identity.js"
import { generatePrivateKey, privateKeyToPem, publicJwk, type Jwk } from "./keys.js"
import { SpiffeId } from "./spiffeId.js"

const SERVICES_DIRNAME = "services"

/** Create an empty provisioning root with an empty bundle. */
export function initRoot(root: string, trustDomain: string): string {
  const bundlePath = join(root, DIR_BUNDLE_FILENAME)
  if (existsSync(bundlePath)) {
    throw new SpiffileError(`already initialized: ${bundlePath}`)
  }
  mkdirSync(join(root, SERVICES_DIRNAME), { recursive: true })
  writeBundleDocument(bundlePath, {
    trust_domain: trustDomain,
    spiffile_version: BUNDLE_VERSION,
    identities: {},
  })
  return root
}

/**
 * Generate a keypair for a service and register its public key in the
 * bundle. Idempotent: a service that already has a key keeps it.
 */
export function addService(root: string, name: string): SpiffeId {
  const bundle = readBundle(root)
  const spiffeId = SpiffeId.parse(`spiffe://${bundle.trustDomain}/${name}`)

  const serviceDir = join(root, SERVICES_DIRNAME, name)
  const keyPath = join(serviceDir, DIR_KEY_FILENAME)
  if (existsSync(keyPath)) {
    return spiffeId
  }

  mkdirSync(serviceDir, { recursive: true })
  const privateKey = generatePrivateKey()
  writeFileSync(keyPath, privateKeyToPem(privateKey))
  chmodSync(keyPath, 0o600)
  writeFileSync(join(serviceDir, DIR_ID_FILENAME), `${spiffeId}\n`)

  setKeys(root, bundle, spiffeId.toString(), [publicJwk(privateKey)])
  return spiffeId
}

/**
 * Generate a new keypair for a service. With keepOld (the default) the
 * previous public key stays in the bundle so in-flight tokens and stale
 * bundle copies keep working.
 */
export function rotateService(root: string, name: string, keepOld = true): SpiffeId {
  const bundle = readBundle(root)
  const spiffeId = SpiffeId.parse(`spiffe://${bundle.trustDomain}/${name}`)

  const keyPath = join(root, SERVICES_DIRNAME, name, DIR_KEY_FILENAME)
  if (!existsSync(keyPath)) {
    throw new SpiffileError(`unknown service '${name}': ${keyPath} does not exist`)
  }

  const privateKey = generatePrivateKey()
  const newJwk = publicJwk(privateKey)
  const existing = keepOld ? (bundle.identities.get(spiffeId.toString()) ?? []) : []
  const keys = [newJwk, ...existing.filter((jwk) => jwk.kid !== newJwk.kid)]

  writeFileSync(keyPath, privateKeyToPem(privateKey))
  chmodSync(keyPath, 0o600)
  setKeys(root, bundle, spiffeId.toString(), keys)
  return spiffeId
}

/** Remove a service's keys from the bundle (revocation) and its directory. */
export function removeService(root: string, name: string): void {
  const bundle = readBundle(root)
  const doc = bundle.toDocument()
  delete doc.identities[`spiffe://${bundle.trustDomain}/${name}`]
  writeBundleDocument(join(root, DIR_BUNDLE_FILENAME), doc)
  rmSync(join(root, SERVICES_DIRNAME, name), { recursive: true, force: true })
}

/** The environment variables that point a consumer at its identity files. */
export function serviceEnv(root: string, name: string): Record<string, string> {
  const serviceDir = join(root, SERVICES_DIRNAME, name)
  return {
    [ENV_ID_FILE]: join(serviceDir, DIR_ID_FILENAME),
    [ENV_KEY_FILE]: join(serviceDir, DIR_KEY_FILENAME),
    [ENV_BUNDLE_FILE]: join(root, DIR_BUNDLE_FILENAME),
  }
}

/** Load a provisioned service's {@link Identity} directly (tests, tooling). */
export function loadIdentity(root: string, name: string): Identity {
  const env = serviceEnv(root, name)
  return Identity.fromFiles(env[ENV_ID_FILE], env[ENV_KEY_FILE], env[ENV_BUNDLE_FILE])
}

// -- internals ---------------------------------------------------------------

function readBundle(root: string): Bundle {
  return Bundle.fromDocument(JSON.parse(readFileSync(join(root, DIR_BUNDLE_FILENAME), "utf8")))
}

function setKeys(root: string, bundle: Bundle, spiffeId: string, keys: Jwk[]): void {
  const doc = bundle.toDocument()
  doc.identities[spiffeId] = { keys }
  writeBundleDocument(join(root, DIR_BUNDLE_FILENAME), doc)
}

function writeBundleDocument(path: string, doc: BundleDocument): void {
  writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`)
}
