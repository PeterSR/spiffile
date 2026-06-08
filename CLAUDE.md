# CLAUDE.md

Guidance for Claude Code (and other agents/contributors) working in this repo.

## What this is

spiffile is **a files profile for SPIFFE plus libraries that implement it**.
Workloads receive their identity (a private key, their SPIFFE ID, and a trust
bundle) as plain files on disk — no agent, no socket, no Workload API. The
profile is as much "the product" as the code; treat `PROFILE.md` as a
specification, not documentation.

Three implementations track one profile and are kept **interchangeable**: a
token minted by any of them verifies in every other.

## Repository layout

| Path | What |
|---|---|
| `PROFILE.md` | the versioned profile spec (file layout, bundle document, JWT-SVID + verification rules) |
| `python/` · `ts/` · `go/` | the three implementations, one self-contained package each |
| `conformance/` | shared `fixtures.json` + the live cross-mint `matrix/` that pin the implementations together |
| `CHANGELOG.md` | one shared changelog; entries note the implementation(s) when not universal |
| `.claude/skills/check-parity/` | the parity-audit skill (run it after touching an implementation) |

The implementations have **at most one runtime dependency each** (Python:
PyJWT; TS: zero; Go: golang-jwt). Keep it that way — new runtime deps need a
strong reason.

## The parity contract — the rule that matters most

> **Any behaviour change lands in all three implementations — and in the
> conformance fixtures, if it changes what's valid — in the same pull
> request.** New behaviour comes with tests in every implementation it touches.

Language-local changes (docs, packaging, idiom, a language's own README) may
touch one directory. A behaviour change that you can't port to all three
should be an issue, not a one-language PR. After touching any implementation,
`PROFILE.md`, or `conformance/`, run the **`check-parity`** skill.

Constants must be identical everywhere: env vars (`SPIFFILE_DIR`,
`SPIFFILE_ID_FILE`, `SPIFFILE_KEY_FILE`, `SPIFFILE_BUNDLE_FILE`), file names
(`id`, `key.pem`, `bundle.json`), defaults (TTL 60s, leeway 30s), `ES256`-only
allow-list, bundle version 1, JWK `use: "jwt-svid"`.

## Build, test, lint

Each implementation is self-contained:

```bash
# Python (needs uv)
cd python && uv sync && uv run pytest -q
uv run ruff check src tests && uv run ruff format --check src tests

# TypeScript (needs Node >= 18, zero runtime deps)
cd ts && npm ci && npm test          # tsc + node --test

# Go (needs Go >= 1.24)
cd go && go test ./... && gofmt -l . && go vet ./...
```

Cross-implementation matrix (needs all three toolchains): `conformance/matrix/run.sh`.
CI must be green across all three suites plus the matrix.

## Changing the profile

`PROFILE.md` is versioned. Anything that changes what producers emit or
verifiers accept should **start as an issue, not a PR** — it ripples through
every implementation and deployment. Editorial fixes (typos, non-behavioural
clarifications) can go straight to PR. Validation-rule changes go through
`conformance/fixtures.json` (`valid_spiffe_ids` / `invalid_spiffe_ids`),
regenerated with the Python implementation — see `conformance/README.md`.

## Versioning & releases — include the bump in the PR

The three libraries are released at the **same version**. When a PR changes a
library's public surface or behaviour, **bump the version and update the
changelog in that same PR** — don't leave it for a separate pass. A version
bump touches all of:

- `python/pyproject.toml`, `python/src/spiffile/__init__.py` (`__version__`), `python/uv.lock`
- `ts/package.json`, `ts/package-lock.json`
- `CHANGELOG.md` — move the `[Unreleased]` entries into a dated `X.Y.Z` section
- Go has no version constant; it is versioned by git tag only.

Pick the bump by semver: new public API → minor (`0.1.0`), fixes only → patch.

Publishing is **tag-driven** and happens only on a deliberate tag push (see
`.github/workflows/publish.yml`):

- `python-vX.Y.Z` → PyPI (trusted publishing) · `ts-vX.Y.Z` → npm (trusted
  publishing + provenance) · `go/vX.Y.Z` → Go module proxy (tag only)

## Working conventions

- **This is a public repository — hold it to a public standard.** Professional,
  self-contained writing in commits, PRs, code comments, and docs. No internal
  references, private hostnames, employer/customer names, scratch notes, or
  "WIP"/"fix typo" history — write as if a stranger is reading, because they
  are. The canonical GitHub owner casing is **`PeterSR`**.
- **Commits must be signed.** Signing is configured (SSH-based via
  `commit.gpgsign` / `tag.gpgsign`); every commit and release tag verifies.
  Don't bypass it (`--no-gpg-sign`), and don't merge unsigned commits.
- **Branch + PR; never push to `main` directly.** Even releases go through a
  PR. Keep PRs focused — separate behaviour changes from refactors.
- **Commit subjects:** declarative, capitalised, no trailing period, no
  automation/tooling trailers (e.g. `Add an unverified audience reader for
  routing and diagnostics`). PR bodies state what changed, why, and how it was
  verified.
- **Verify parity before merge.** A feature isn't done until all three
  implementations are on-par. Run the `check-parity` skill — all three suites
  green plus the cross-mint matrix — before merging, and ideally on the commit
  that wraps up a feature, not just at the end. CI runs the same checks; a red
  matrix is a parity break, never a flake.
- **Keep the changelog current.** Land user-facing changes with a
  `CHANGELOG.md` `[Unreleased]` entry in the same PR, so cutting a release is
  only a version bump and a date.
- **Release tags** are signed annotated tags on the merged release commit,
  named `python-vX.Y.Z` / `ts-vX.Y.Z` / `go/vX.Y.Z`, message
  `spiffile <Language> library vX.Y.Z`. Pushing a tag publishes — only tag a
  commit already merged to `main` with green CI.
- **Security:** report suspected vulnerabilities privately per `SECURITY.md`;
  never commit real keys or tokens — test material is generated under temp
  dirs and fixed fixtures.
