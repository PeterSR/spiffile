/**
 * Trust bundle: the document binding SPIFFE IDs to their public keys.
 * Per-identity binding is what makes the self-issued model safe — a key may
 * only validate tokens whose `sub` it is bound to. See PROFILE.md.
 */
import { readFileSync, statSync } from "node:fs"

import { InvalidBundleError, InvalidSpiffeIdError, UnknownIdentityError } from "./errors.js"
import { SpiffeId } from "./spiffeId.js"
import type { Jwk } from "./keys.js"

export const BUNDLE_VERSION = 1

export type BundleDocument = {
  trust_domain: string
  spiffile_version: number
  identities: Record<string, { keys: Jwk[] }>
}

const warn: (message: string) => void =
  typeof process !== "undefined" && process.emitWarning
    ? (message) => process.emitWarning(message, "SpiffileBundleWarning")
    : console.warn

export class Bundle {
  readonly trustDomain: string
  readonly identities: ReadonlyMap<string, Jwk[]>

  constructor(trustDomain: string, identities: Map<string, Jwk[]>) {
    this.trustDomain = trustDomain
    this.identities = identities
  }

  static fromDocument(doc: unknown): Bundle {
    if (typeof doc !== "object" || doc === null) {
      throw new InvalidBundleError("bundle is not an object")
    }
    const { trust_domain, spiffile_version, identities } = doc as Partial<BundleDocument>
    if (typeof trust_domain !== "string" || spiffile_version === undefined || typeof identities !== "object" || identities === null) {
      throw new InvalidBundleError("bundle is missing a required member (trust_domain, spiffile_version, identities)")
    }
    if (spiffile_version !== BUNDLE_VERSION) {
      throw new InvalidBundleError(`unsupported spiffile_version: ${spiffile_version}`)
    }

    // A malformed entry must not take down verification for everyone else
    // in the bundle: skip it (loudly) instead of failing the parse.
    const parsed = new Map<string, Jwk[]>()
    for (const [rawId, jwks] of Object.entries(identities)) {
      let spiffeId: SpiffeId
      try {
        spiffeId = SpiffeId.parse(rawId)
      } catch (error) {
        if (error instanceof InvalidSpiffeIdError) {
          warn(`skipping invalid bundle entry '${rawId}': ${error.message}`)
          continue
        }
        throw error
      }
      if (spiffeId.trustDomain !== trust_domain) {
        warn(`skipping bundle entry '${rawId}': not in trust domain '${trust_domain}'`)
        continue
      }
      const keys = jwks && typeof jwks === "object" ? jwks.keys : undefined
      if (!Array.isArray(keys) || keys.length === 0) {
        warn(`skipping bundle entry '${rawId}': no keys`)
        continue
      }
      parsed.set(spiffeId.toString(), keys)
    }
    return new Bundle(trust_domain, parsed)
  }

  toDocument(): BundleDocument {
    return {
      trust_domain: this.trustDomain,
      spiffile_version: BUNDLE_VERSION,
      identities: Object.fromEntries([...this.identities].map(([id, keys]) => [id, { keys }])),
    }
  }

  keysFor(spiffeId: string): Jwk[] {
    const keys = this.identities.get(spiffeId)
    if (!keys) {
      throw new UnknownIdentityError(`no keys in trust bundle for '${spiffeId}'`)
    }
    return keys
  }
}

/**
 * Reads a bundle from a file, hot-reloading when the file changes
 * (mtime+size), so secret-sync style updates are picked up without restarts.
 */
export class FileBundleSource {
  readonly path: string
  private stamp: string | null = null
  private bundle: Bundle | null = null

  constructor(path: string) {
    this.path = path
  }

  get(): Bundle {
    const stat = statSync(this.path)
    const stamp = `${stat.mtimeMs}:${stat.size}`
    if (this.bundle === null || stamp !== this.stamp) {
      let doc: unknown
      try {
        doc = JSON.parse(readFileSync(this.path, "utf8"))
      } catch (error) {
        throw new InvalidBundleError(`cannot read bundle at ${this.path}: ${error}`)
      }
      this.bundle = Bundle.fromDocument(doc)
      this.stamp = stamp
    }
    return this.bundle
  }
}
