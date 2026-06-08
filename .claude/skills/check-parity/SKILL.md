---
name: check-parity
description: Verify that the Python, TypeScript and Go implementations of the spiffile profile have not drifted — same API surface, same validation rules, same crypto, tokens interoperate. Run after touching any implementation, the PROFILE, or periodically.
---

# Check implementation parity

The spiffile promise is that all implementations are interchangeable: same
validation rules, same thumbprints, same defaults, and a token minted by any
implementation verifies in every other. This skill checks that promise.

## 1. Run every test suite

```bash
(cd python && uv run pytest -q)
(cd ts && npm test)
(cd go && go test ./...)
```

All suites include the shared fixtures (`conformance/fixtures.json`): JWK/kid
reproduction from a fixed key, a Python-minted token verifying, and the
SPIFFE-ID validation vectors. A failure here is a parity break, not a flake.

## 2. Run the live cross-mint matrix

```bash
conformance/matrix/run.sh
```

Provisions a fresh root, then every implementation mints a token that every
other implementation must verify (6 pairs). This catches drift the static
fixtures can't (e.g. minting-side regressions).

## 3. Audit the API surface against the parity matrix

Every row must exist in every implementation (idiomatic naming per language
is fine; *capability* must match):

| Capability | Python | TypeScript | Go |
|---|---|---|---|
| SPIFFE ID parse/validate | `SpiffeId.parse` | `SpiffeId.parse` | `ParseSpiffeID` |
| Generate key (EC P-256) | `keys.generate_private_key` | `generatePrivateKey` | `GeneratePrivateKeyPEM` |
| Public JWK + RFC 7638 kid | `keys.public_jwk` | `publicJwk` | `PublicJWKFromPEM` |
| Bundle parse (resilient: skip+warn bad entries) | `Bundle.from_dict` | `Bundle.fromDocument` | `ParseBundle` |
| Bundle hot-reload source | `FileBundleSource` | `FileBundleSource` | `FileBundleSource` |
| Identity from files/env | `Identity.from_files/.from_env` | `Identity.fromFiles/.fromEnv` | `FromFiles/FromEnv` |
| Mint (aud-bound, default 60s) | `.token` | `.token` | `.Token` |
| Verify (aud=self default, 30s leeway, ES256-only) | `.verify` | `.verify` | `.Verify` |
| Unverified aud read (routing/diagnostics; rejects array aud) | `unverified_audience` | `unverifiedAudience` | `UnverifiedAudience` |
| **Signing key hot-reload** | yes | yes | yes |
| Provision: init/add/rotate/remove/env/load | `provision.*` | `provision.*` | `InitRoot` etc. |

Also check constants are identical everywhere: env var names (`SPIFFILE_DIR`,
`SPIFFILE_ID_FILE`, `SPIFFILE_KEY_FILE`, `SPIFFILE_BUNDLE_FILE`), file names
(`id`, `key.pem`, `bundle.json`), defaults (TTL 60s, leeway 30s), algorithm
allow-list (`ES256` only), bundle version (1), JWK `use: "jwt-svid"`.

## 4. Check behavior semantics (read the code, not just names)

- Verification scopes key lookup by the claimed `sub` (the per-identity
  binding) — never a global kid lookup.
- Algorithm comes from the allow-list, never the token header.
- Unknown identity → the dedicated error type; everything else → invalid
  token error.
- Required claims enforced: `sub`, `aud`, `exp`; `aud` must be a single
  string — array audiences are rejected even when they contain the expected
  audience.
- Rotation overlap: old key kept in bundle keeps old tokens valid; revoked
  key (or removed identity) makes them fail.

## 5. Check PROFILE.md against reality

Skim [PROFILE.md](../../../PROFILE.md): does any implementation accept
something the profile forbids, or vice versa? Validation rule changes MUST
land in the fixtures (`conformance/fixtures.json` → `invalid_spiffe_ids` /
`valid_spiffe_ids`) and in all three implementations in the same change.

## 6. Report

Produce a short parity report: suites (pass/fail per lib), cross-mint matrix
result, any surface/constant/semantic gaps found, and concrete file:line
pointers for each gap. If fixtures need regenerating (only when the profile
deliberately changes), regenerate them with the Python implementation and
re-run everything.
