#!/usr/bin/env bash
# Live cross-implementation matrix: every implementation mints a token that
# every OTHER implementation must verify (one shared provisioned root).
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
ROOT="$(mktemp -d)/identity"

echo "== building =="
(cd "$REPO/ts" && npm run --silent build)
(cd cli_go && go mod tidy >/dev/null 2>&1 && go build -o /tmp/spiffile-parity-go .)

py() { (cd "$REPO/python" && uv run python "$REPO/conformance/matrix/cli.py" "$@"); }
ts() { node cli.mjs "$@"; }
golang() { /tmp/spiffile-parity-go "$@"; }

echo "== provisioning (python) =="
py provision "$ROOT"

echo "== cross-mint matrix =="
for minter in py ts golang; do
  TOKEN=$($minter mint "$ROOT" orders billing)
  for verifier in py ts golang; do
    if [ "$minter" != "$verifier" ]; then
      printf "%-6s mint -> %-6s verify: " "$minter" "$verifier"
      $verifier verify "$ROOT" billing "$TOKEN" orders
    fi
  done
done

echo "== all 6 cross pairs verified =="
