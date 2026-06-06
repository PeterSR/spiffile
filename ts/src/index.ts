/**
 * spiffile — SPIFFE identities delivered as files, no agents.
 *
 * Implements the SPIFFE identity documents (SPIFFE-ID, JWT-SVID, trust
 * bundles); SVID material and bundles arrive as files written by whatever
 * infrastructure you already trust. See PROFILE.md for the file layout and
 * bundle format.
 */
export { SpiffeId } from "./spiffeId.js"
export {
  SpiffileError,
  InvalidSpiffeIdError,
  InvalidBundleError,
  UnknownIdentityError,
  InvalidTokenError,
} from "./errors.js"
export { Bundle, FileBundleSource, BUNDLE_VERSION, type BundleDocument } from "./bundle.js"
export {
  generatePrivateKey,
  privateKeyToPem,
  privateKeyFromPem,
  publicJwk,
  jwkThumbprint,
  ALGORITHM,
  JWT_SVID_USE,
  type Jwk,
} from "./keys.js"
export {
  Identity,
  type Caller,
  DEFAULT_TTL_SECONDS,
  DEFAULT_LEEWAY_SECONDS,
  ALLOWED_ALGORITHMS,
  ENV_DIR,
  ENV_ID_FILE,
  ENV_KEY_FILE,
  ENV_BUNDLE_FILE,
} from "./identity.js"
export * as provision from "./provision.js"
