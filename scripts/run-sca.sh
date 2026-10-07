#!/usr/bin/env bash
# P03-002: explicit local inventory and approved public vulnerability lookup.
set -euo pipefail
ROOT="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
exec /usr/bin/node "$ROOT/scripts/run-sca.cjs" "$@"
