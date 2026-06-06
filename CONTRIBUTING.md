# Contributing

Thanks for considering a contribution. spiffile is deliberately small —
a few pages of profile and three thin implementations — and contributions
that keep it that way are the most welcome kind.

## Repository layout

| Path | What |
|---|---|
| [PROFILE.md](PROFILE.md) | the profile specification — as much "the product" as the code |
| [python/](python/) · [ts/](ts/) · [go/](go/) | the implementations, one per directory |
| [conformance/](conformance/) | shared fixtures + the live cross-mint matrix that pin the implementations together |

## Development setup

Each implementation is self-contained:

```bash
# Python (needs uv)
cd python && uv sync
uv run pytest
uv run ruff check src tests && uv run ruff format --check src tests

# TypeScript (needs Node >= 18)
cd ts && npm ci
npm test            # tsc + node --test

# Go (needs Go >= 1.24)
cd go && go test ./...
gofmt -l . && go vet ./...
```

And the cross-implementation matrix (needs all three toolchains):

```bash
conformance/matrix/run.sh
```

## The parity contract

The project's core promise is that the implementations are interchangeable:
same validation rules, same constants, same crypto, and a token minted by
any implementation verifies in every other. That has one practical
consequence for contributors:

> **Any behavior change lands in all three implementations — and in the
> conformance fixtures, if it changes what's valid — in the same pull
> request.**

A change to one implementation only is fine when it's genuinely
language-local (docs, packaging, idiom). If you can't port a behavior change
to all three, open an issue describing it instead — that's a useful
contribution too.

Validation rule changes go through `conformance/fixtures.json`
(`valid_spiffe_ids` / `invalid_spiffe_ids`); see
[conformance/README.md](conformance/README.md) for regeneration.

## Changing the profile

[PROFILE.md](PROFILE.md) is a versioned specification. Anything that affects
what producers emit or verifiers accept should start as an issue, not a PR —
profile changes ripple through every implementation and every deployment.
Editorial fixes (typos, clarifications that don't change behavior) can go
straight to PR.

## Porting to a new language

Ports are welcome. A new implementation should:

1. implement the full surface in the parity table
   (mint, verify, bundle hot-reload, provisioning primitives),
2. pin its test suite to `conformance/fixtures.json`,
3. add a mint/verify CLI to `conformance/matrix/`,
4. keep dependencies minimal (each current implementation has at most one
   runtime dependency).

## Pull requests

- Keep PRs focused; separate behavior changes from refactors.
- CI must be green: all three suites plus the cross-implementation matrix.
- New behavior comes with tests — in every implementation it touches.
