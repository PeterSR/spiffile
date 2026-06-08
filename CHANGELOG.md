# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The libraries are versioned and released independently (`python-vX.Y.Z`,
`ts-vX.Y.Z`, `go/vX.Y.Z` tags) but track the same profile; entries below
note the implementation(s) they apply to when not universal.

## [Unreleased]

## 0.1.0 — 2026-06-08

`python-v0.1.0` (PyPI), `ts-v0.1.0` (npm), `go/v0.1.0`.

### Added

- Read a JWT-SVID's `aud` claim without verifying the signature, for routing
  and diagnostics (e.g. picking which trust context to verify under):
  `unverified_audience` (Python), `unverifiedAudience` (TypeScript),
  `UnverifiedAudience` (Go). All reject an array `aud` and report a missing
  `aud` as empty (`None`/`null`/`""`); the result is attacker-controlled and
  must always be followed by `verify`.

## 0.0.2 — 2026-06-06

First public release: `python-v0.0.2` (PyPI), `ts-v0.0.2` (npm),
`go/v0.0.2`. (The same-day 0.0.1 releases were superseded by packaging
fixes.)

### Added

- The spiffile profile v0 ([PROFILE.md](PROFILE.md)): file layout,
  per-identity trust bundle document, JWT-SVID requirements, verification
  rules.
- Python, TypeScript and Go implementations covering the full surface:
  mint, verify (hot-reloading bundle and signing key), and provisioning
  primitives (init/add/rotate/remove).
- Shared conformance suite ([conformance/](conformance/)): static
  cross-implementation fixtures plus a live cross-mint matrix, both run in
  CI.

[Unreleased]: https://github.com/PeterSR/spiffile/commits/main
