/**
 * Key generation, JWK encoding and RFC 7638 thumbprints.
 * Profile v0 uses EC P-256 keys with ES256 signatures exclusively.
 */
import { createHash, generateKeyPairSync, createPrivateKey, type KeyObject } from "node:crypto"

/** Per the SPIFFE Trust Domain and Bundle standard. */
export const JWT_SVID_USE = "jwt-svid"
export const ALGORITHM = "ES256"

export interface Jwk {
  kty: string
  crv: string
  x: string
  y: string
  kid: string
  use: string
  alg: string
  [extra: string]: unknown
}

export function generatePrivateKey(): KeyObject {
  return generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey
}

export function privateKeyToPem(key: KeyObject): string {
  return key.export({ type: "pkcs8", format: "pem" }).toString()
}

export function privateKeyFromPem(pem: string | Buffer): KeyObject {
  const key = createPrivateKey({ key: pem, format: "pem" })
  if (key.asymmetricKeyType !== "ec") {
    throw new TypeError(`expected an EC private key, got ${key.asymmetricKeyType}`)
  }
  return key
}

/** The public JWK (with RFC 7638 thumbprint as kid) for a private key. */
export function publicJwk(key: KeyObject): Jwk {
  const exported = key.export({ format: "jwk" }) as { kty: string; crv: string; x: string; y: string }
  const jwk: Jwk = {
    kty: exported.kty,
    crv: exported.crv,
    x: exported.x,
    y: exported.y,
    kid: "",
    use: JWT_SVID_USE,
    alg: ALGORITHM,
  }
  jwk.kid = jwkThumbprint(jwk)
  return jwk
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url). */
export function jwkThumbprint(jwk: Pick<Jwk, "kty" | "crv" | "x" | "y">): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
  return createHash("sha256").update(canonical).digest("base64url")
}
