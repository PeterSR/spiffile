# Conformance suite

Shared test material that keeps every spiffile implementation honest: all
test suites (and any future port) are pinned to the same data, and CI runs
the live matrix on every push and pull request.

## fixtures.json

Static cross-implementation fixtures:

- pinned EC P-256 private keys, plus the JWKs (including the RFC 7638
  thumbprint `kid`s) every implementation must derive from them,
- a bundle document, and a token minted by the Python reference
  implementation that every implementation must verify,
- SPIFFE-ID validation vectors (`valid_spiffe_ids` / `invalid_spiffe_ids`).

Regenerate only when the profile deliberately changes — the derived values
are pinned by all test suites:

```bash
cd python && uv sync && uv run python ../conformance/generate.py
```

The private keys and validation vectors are inputs and survive regeneration
verbatim; JWKs, bundle and token are re-derived.

## matrix/

The live cross-mint matrix: provisions a fresh identity root, then every
implementation mints a token that every other implementation must verify
(6 pairs). This catches minting-side drift the static fixtures can't.

```bash
conformance/matrix/run.sh   # requires uv, Node >= 18, Go >= 1.24
```

Porting spiffile to a new language? Pin its test suite to `fixtures.json`
and add a mint/verify CLI to the matrix.
