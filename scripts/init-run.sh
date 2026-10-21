#!/usr/bin/env bash
# Clear previous results so stale evidence can never be mistaken for this run.
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p reports/scanners reports/raw
rm -f reports/scanners/*.json reports/verdict.json
echo "[+] Run initialised: previous scanner results cleared"
