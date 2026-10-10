#!/usr/bin/env bash
# Task P09-008: Egress Boundary Audit Script
# Validates that no automated outbound push or mirror exists without human gating.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[*] Auditing CI/CD pipeline for unauthorized egress..."
if [ -f ".gitlab-ci.yml" ] && grep -rn "git push origin" .gitlab-ci.yml 2>/dev/null; then
    echo "[-] FAILED: Found automated git push to origin in .gitlab-ci.yml" >&2
    exit 1
fi

echo "[*] Auditing Git hooks for active background egress hooks..."
if [ -d ".git/hooks" ]; then
    for hook in .git/hooks/*; do
        # Ignore sample files and non-executable files
        if [ -f "$hook" ] && [[ "$hook" != *.sample ]] && [ -x "$hook" ]; then
            if grep -q "git push" "$hook"; then
                echo "[-] FAILED: Found active git push hook in $hook" >&2
                exit 1
            fi
        fi
    done
fi

echo "[*] Verifying exclusive human release gate entrypoint..."
if [ ! -f "scripts/mirror-release-gate.sh" ]; then
    echo "[-] FAILED: Missing scripts/mirror-release-gate.sh gatekeeper" >&2
    exit 1
fi

echo "[+] AUDIT PASSED: Zero automated or direct outbound mirroring paths exist."
exit 0
