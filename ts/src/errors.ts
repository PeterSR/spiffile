/** Base class for all spiffile errors. */
export class SpiffileError extends Error {}

/** A string is not a valid SPIFFE ID. */
export class InvalidSpiffeIdError extends SpiffileError {}

/** A bundle document is malformed or does not match the profile. */
export class InvalidBundleError extends SpiffileError {}

/** The claimed identity has no keys in the trust bundle. */
export class UnknownIdentityError extends SpiffileError {}

/** A token failed verification (signature, audience, expiry, claims). */
export class InvalidTokenError extends SpiffileError {}
