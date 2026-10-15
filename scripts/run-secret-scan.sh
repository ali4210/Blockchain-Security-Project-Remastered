#!/usr/bin/env bash
set -e

echo "[+] [ZONE 1] Running Native Gitleaks High-Entropy Secret & Key Leak Detection..."

mkdir -p reports

if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --gitleaks-ignore-path=.gitleaksignore \
        --source . \
        --no-git \
        --verbose \
        --report-format json \
        --report-path reports/gitleaks-report.json || true

    LEAK_COUNT=$(jq '. | length' reports/gitleaks-report.json 2>/dev/null || echo "0")
    echo "    -> Native Gitleaks scan completed. Findings identified: ${LEAK_COUNT}"
    echo "    -> Telemetry stored: reports/gitleaks-report.json"
else
    echo "[-] Gitleaks binary not located; running fallback pattern scan..."
    FOUND_LEAKS=$(grep -rE "(0x[a-fA-F0-9]{64}|BEGIN PRIVATE KEY|AKIA[0-9A-Z]{16})" \
        --exclude-dir={node_modules,.git,cache,artifacts,data,reports} . 2>/dev/null | wc -l || echo "0")
    echo "    -> Fallback entropy scan completed. Discovered potential patterns: ${FOUND_LEAKS}"
fi
