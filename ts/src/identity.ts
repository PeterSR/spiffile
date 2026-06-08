/**
 * Workload identity: mint and verify JWT-SVIDs from file-delivered material.
 * Zero dependencies — JWS compact serialization via node:crypto (ES256 with
 * IEEE P1363 signatures, as JOSE requires).
 */
import { createPublicKey, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from "node:crypto"
import { readFileSync, statSync } from "node:fs"
import { join } from "node:path"

import { Bundle, FileBundleSource } from "./bundle.js"
import { InvalidTokenError, SpiffileError } from "./errors.js"
import { ALGORITHM, privateKeyFromPem, publicJwk, type Jwk } from "./keys.js"
import { SpiffeId } from "./spiffeId.js"

export const DEFAULT_TTL_SECONDS = 60
export const DEFAULT_LEEWAY_SECONDS = 30

/** Profile v0: ES256 only. A verifier MUST reject anything else. */
export const ALLOWED_ALGORITHMS = [ALGORITHM]

export const ENV_DIR = "SPIFFILE_DIR"
export const ENV_ID_FILE = "SPIFFILE_ID_FILE"
export const ENV_KEY_FILE = "SPIFFILE_KEY_FILE"
export const ENV_BUNDLE_FILE = "SPIFFILE_BUNDLE_FILE"

export const DIR_ID_FILENAME = "id"
export const DIR_KEY_FILENAME = "key.pem"
export const DIR_BUNDLE_FILENAME = "bundle.json"

/** The verified peer of an inbound request. */
export interface Caller {
  id: SpiffeId
  claims: Record<string, unknown>
}

const b64url = (data: Buffer | string): string => Buffer.from(data).toString("base64url")

/**
 * Reads the private key from a file, hot-reloading when it changes.
 * Key rotation replaces the key file; signing must pick the new key up
 * without a process restart — otherwise tokens break once the rotated-out
 * public key is pruned from peers' bundles.
 */
class FileKeySource {
  private stamp: string | null = null
  private key: KeyObject | null = null
  private kid = ""

  constructor(private readonly path: string) {}

  get(): { key: KeyObject; kid: string } {
    const stat = statSync(this.path)
    const stamp = `${stat.mtimeMs}:${stat.size}`
    if (this.key === null || stamp !== this.stamp) {
      this.key = privateKeyFromPem(readFileSync(this.path))
      this.kid = publicJwk(this.key).kid
      this.stamp = stamp
    }
    return { key: this.key, kid: this.kid }
  }
}

class StaticKeySource {
  private readonly key: KeyObject
  private readonly kid: string

  constructor(key: KeyObject) {
    this.key = key
    this.kid = publicJwk(key).kid
  }

  get(): { key: KeyObject; kid: string } {
    return { key: this.key, kid: this.kid }
  }
}

/** A service's own identity plus the trust bundle to verify peers against. */
export class Identity {
  readonly id: SpiffeId
  private readonly keySource: FileKeySource | StaticKeySource
  private readonly bundleSource: FileBundleSource

  constructor(id: SpiffeId, privateKey: KeyObject | FileKeySource, bundleSource: FileBundleSource) {
    this.id = id
    this.keySource = privateKey instanceof FileKeySource ? privateKey : new StaticKeySource(privateKey)
    this.bundleSource = bundleSource
  }

  // -- construction --------------------------------------------------------

  static fromFiles(idFile: string, keyFile: string, bundleFile: string): Identity {
    const spiffeId = SpiffeId.parse(readFileSync(idFile, "utf8").trim())
    return new Identity(spiffeId, new FileKeySource(keyFile), new FileBundleSource(bundleFile))
  }

  /**
   * Load identity from environment configuration: either SPIFFILE_DIR (a
   * directory containing id, key.pem and bundle.json) or the three explicit
   * file variables, which take precedence per variable.
   */
  static fromEnv(env: Record<string, string | undefined> = process.env): Identity {
    const dir = env[ENV_DIR]
    const idFile = env[ENV_ID_FILE] ?? (dir ? join(dir, DIR_ID_FILENAME) : undefined)
    const keyFile = env[ENV_KEY_FILE] ?? (dir ? join(dir, DIR_KEY_FILENAME) : undefined)
    const bundleFile = env[ENV_BUNDLE_FILE] ?? (dir ? join(dir, DIR_BUNDLE_FILENAME) : undefined)
    if (!idFile || !keyFile || !bundleFile) {
      throw new SpiffileError(
        `identity not configured: set ${ENV_DIR}, or ${ENV_ID_FILE} + ${ENV_KEY_FILE} + ${ENV_BUNDLE_FILE}`,
      )
    }
    return Identity.fromFiles(idFile, keyFile, bundleFile)
  }

  // -- outbound -------------------------------------------------------------

  /** Mint a JWT-SVID for a single target audience. */
  token(audience: string | SpiffeId, ttl: number = DEFAULT_TTL_SECONDS): string {
    const audienceId = audience instanceof SpiffeId ? audience : SpiffeId.parse(audience)
    const { key, kid } = this.keySource.get()
    const now = Math.floor(Date.now() / 1000)
    const header = { alg: ALGORITHM, typ: "JWT", kid }
    const claims = {
      sub: this.id.toString(),
      aud: audienceId.toString(),
      iat: now,
      exp: now + ttl,
    }
    const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`
    const signature = cryptoSign("sha256", Buffer.from(signingInput), { key, dsaEncoding: "ieee-p1363" })
    return `${signingInput}.${signature.toString("base64url")}`
  }

  // -- inbound --------------------------------------------------------------

  /**
   * Verify an inbound JWT-SVID and return the verified caller.
   * `audience` defaults to this identity's own SPIFFE ID.
   *
   * Throws UnknownIdentityError if the claimed identity has no keys in the
   * bundle, InvalidTokenError for everything else.
   */
  verify(token: string, audience?: string | SpiffeId, leeway: number = DEFAULT_LEEWAY_SECONDS): Caller {
    const expectedAudience = (audience ?? this.id).toString()

    const parts = token.split(".")
    if (parts.length !== 3) {
      throw new InvalidTokenError("malformed token: expected three dot-separated segments")
    }
    let header: { alg?: string; kid?: string }
    let claims: Record<string, unknown>
    try {
      header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"))
      claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))
    } catch (error) {
      throw new InvalidTokenError(`malformed token: ${error}`)
    }

    // Algorithm pinning: the allow-list decides, never the token header.
    if (!header.alg || !ALLOWED_ALGORITHMS.includes(header.alg)) {
      throw new InvalidTokenError(`token rejected: algorithm ${header.alg} is not allowed`)
    }
    const claimedSub = claims.sub
    if (typeof claimedSub !== "string" || !claimedSub) {
      throw new InvalidTokenError("token has no sub claim")
    }
    const claimedId = SpiffeId.parse(claimedSub)

    // The profile requires aud to be a single string; strict equality also
    // rejects array audiences, even ones containing the expected value.
    if (claims.aud !== expectedAudience) {
      throw new InvalidTokenError("token rejected: audience doesn't match")
    }
    const now = Date.now() / 1000
    if (typeof claims.exp !== "number") {
      throw new InvalidTokenError("token rejected: missing exp claim")
    }
    if (claims.exp + leeway < now) {
      throw new InvalidTokenError("token rejected: expired")
    }
    if (typeof claims.iat === "number" && claims.iat - leeway > now) {
      throw new InvalidTokenError("token rejected: issued in the future")
    }

    // The security pivot of the profile: only keys bound to the claimed
    // identity in the bundle may validate it. May throw UnknownIdentityError.
    const boundJwks = this.bundleSource.get().keysFor(claimedId.toString())
    const candidates = boundJwks.filter((jwk) => jwk.kid === header.kid)
    const signature = Buffer.from(parts[2], "base64url")
    const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`)

    for (const jwk of candidates.length > 0 ? candidates : boundJwks) {
      let publicKey: KeyObject
      try {
        publicKey = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: "jwk" })
      } catch {
        continue
      }
      if (cryptoVerify("sha256", signingInput, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature)) {
        return { id: claimedId, claims }
      }
    }
    throw new InvalidTokenError(`signature does not match any key bound to '${claimedSub}'`)
  }
}

/**
 * Read a JWT-SVID's `aud` claim WITHOUT verifying the signature.
 *
 * For routing and diagnostics only — e.g. choosing which trust context to
 * verify under when the caller has not stated an expected audience. The result
 * is attacker-controlled; never use it for an access decision, always follow
 * up with {@link Identity.verify}.
 *
 * Returns `null` when the token carries no `aud`. Rejects a non-string (e.g.
 * array) `aud` so callers don't silently treat a multi-audience token as
 * single-audience.
 */
export function unverifiedAudience(token: string): string | null {
  const parts = token.split(".")
  if (parts.length !== 3) {
    throw new InvalidTokenError("malformed token: expected three dot-separated segments")
  }
  let claims: Record<string, unknown>
  try {
    claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))
  } catch (error) {
    throw new InvalidTokenError(`malformed token: ${error}`)
  }
  const aud = claims.aud
  if (aud === undefined || aud === null) {
    return null
  }
  if (typeof aud !== "string") {
    throw new InvalidTokenError("aud must be a single string audience")
  }
  return aud
}

export { FileKeySource }

/** Re-exported for provisioning and tests. */
export type { Bundle }
