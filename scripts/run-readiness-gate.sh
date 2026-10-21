#!/usr/bin/env bash
# Runs the existing deny-by-default gate and records its REAL decision (no `|| true` discarding it).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
RES() { python3 scripts/lib/scanner_result.py "$@"; }
echo "[+] [ZONE 2] Running Deny-by-Default Production Readiness Gate..."
mkdir -p reports/raw reports/scanners
OUT=reports/raw/production-readiness.json
node scripts/production-readiness.cjs --check-production-readiness >"$OUT" 2>/tmp/readiness.err
RC=$?
cat "$OUT"
DEC=$(jq -r '.decision // empty' "$OUT" 2>/dev/null)
REASONS=$(jq -r '(.reasons // []) | join(",")' "$OUT" 2>/dev/null)
if [ -z "$DEC" ]; then
  RES readiness production-readiness error --detail "gate produced no decision (exit $RC): $(tail -n1 /tmp/readiness.err)"; exit 0
fi
RES readiness production-readiness ok --raw "$OUT" --counts "{\"exit_code\": $RC}" \
  --detail "decision=$DEC${REASONS:+ reasons=$REASONS}" --extra "{\"decision\": \"$DEC\"}"
exit 0
