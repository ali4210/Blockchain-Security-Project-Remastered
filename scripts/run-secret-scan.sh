#!/usr/bin/env bash
# Zone 1: real native Gitleaks secret/key-leak detection.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
RES() { python3 scripts/lib/scanner_result.py "$@"; }

echo "[+] [ZONE 1] Running Native Gitleaks High-Entropy Secret & Key Leak Detection..."

mkdir -p reports
RAW=reports/gitleaks-report.json
rm -f "$RAW"

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "[-] Gitleaks binary not located; running fallback pattern scan (NOT a substitute for real gitleaks -- reported as not_run, never disguised as a real scan)..."
    FOUND_LEAKS=$(grep -rE "(0x[a-fA-F0-9]{64}|BEGIN PRIVATE KEY|AKIA[0-9A-Z]{16})" \
        --exclude-dir={node_modules,.git,cache,artifacts,data,reports} . 2>/dev/null | wc -l || echo "0")
    echo "    -> fallback heuristic grep matched ${FOUND_LEAKS} line(s) -- informational only, not a real gitleaks run"
    RES gitleaks gitleaks not_run --detail "gitleaks binary not installed; fallback heuristic grep found ${FOUND_LEAKS} candidate line(s) but this is not a real scan"
    exit 0
fi

VER=$(gitleaks version 2>/dev/null | tail -n1)
gitleaks detect \
    --source . \
    --config .gitleaks.toml \
    --no-git \
    --verbose \
    --report-format json \
    --report-path "$RAW"
RC=$?

# gitleaks' own exit-code contract: 0 = ran clean (no leaks), 1 = ran and
# found real leaks (NOT a tool failure -- a leak existing is exactly what a
# real scan is supposed to report), anything else = the tool itself failed.
if [ "$RC" -ne 0 ] && [ "$RC" -ne 1 ]; then
    RES gitleaks gitleaks error --version "$VER" --detail "gitleaks exited $RC (not the real 0/1 clean/leaks-found contract)"
    exit 0
fi
if [ ! -s "$RAW" ]; then
    RES gitleaks gitleaks error --version "$VER" --detail "gitleaks exited $RC but produced no report at $RAW"
    exit 0
fi

LEAK_COUNT=$(jq '. | length' "$RAW" 2>/dev/null || echo "0")
echo "    -> Native Gitleaks scan completed. Findings identified: ${LEAK_COUNT}"
echo "    -> Telemetry stored: $RAW"
RES gitleaks gitleaks ok --version "$VER" --raw "$RAW" --counts "{\"leaks\": ${LEAK_COUNT}}" \
    --detail "real gitleaks scan, ${LEAK_COUNT} finding(s)"
exit 0
