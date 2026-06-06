/**
 * SPIFFE ID parsing and validation. The rules are identical across all
 * spiffile implementations (see the cross-implementation fixtures).
 */
import { InvalidSpiffeIdError } from "./errors.js"

const SCHEME = "spiffe://"
const TRUST_DOMAIN_RE = /^[a-z0-9._-]+$/
const PATH_SEGMENT_RE = /^[a-zA-Z0-9._-]+$/

export class SpiffeId {
  readonly trustDomain: string
  /** Empty string, or starts with "/". */
  readonly path: string

  private constructor(trustDomain: string, path: string) {
    this.trustDomain = trustDomain
    this.path = path
  }

  static parse(value: string): SpiffeId {
    if (typeof value !== "string" || !value.startsWith(SCHEME)) {
      throw new InvalidSpiffeIdError(`not a SPIFFE ID (missing '${SCHEME}' scheme): ${value}`)
    }
    const rest = value.slice(SCHEME.length)
    const slashIndex = rest.indexOf("/")
    const trustDomain = slashIndex === -1 ? rest : rest.slice(0, slashIndex)
    const path = slashIndex === -1 ? null : rest.slice(slashIndex + 1)

    if (!trustDomain) {
      throw new InvalidSpiffeIdError(`empty trust domain: ${value}`)
    }
    if (!TRUST_DOMAIN_RE.test(trustDomain)) {
      throw new InvalidSpiffeIdError(
        `trust domain may only contain lowercase letters, digits, '.', '_' and '-': ${value}`,
      )
    }

    if (path !== null) {
      if (!path) {
        throw new InvalidSpiffeIdError(`trailing slash is not allowed: ${value}`)
      }
      for (const segment of path.split("/")) {
        if (!segment) {
          throw new InvalidSpiffeIdError(`empty path segment: ${value}`)
        }
        if (segment === "." || segment === "..") {
          throw new InvalidSpiffeIdError(`relative path segment '${segment}' is not allowed: ${value}`)
        }
        if (!PATH_SEGMENT_RE.test(segment)) {
          throw new InvalidSpiffeIdError(
            `path segments may only contain letters, digits, '.', '_' and '-': ${value}`,
          )
        }
      }
    }

    return new SpiffeId(trustDomain, path !== null ? `/${path}` : "")
  }

  toString(): string {
    return `${SCHEME}${this.trustDomain}${this.path}`
  }
}
