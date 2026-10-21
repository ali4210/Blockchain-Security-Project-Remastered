#!/usr/bin/env bash
# Zone 2: real Trivy filesystem/IaC scan (+ optional images: TRIVY_IMAGES="img1 img2").
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
RES() { python3 scripts/lib/scanner_result.py "$@"; }
echo "[+] [ZONE 2] Running Trivy (vuln + misconfig, HIGH/CRITICAL)..."
mkdir -p reports/raw reports/scanners
RAW=reports/raw/trivy-report.json
rm -f "$RAW"
command -v trivy >/dev/null 2>&1 || { RES trivy trivy not_run --detail "trivy not installed"; exit 0; }
VER=$(trivy --version 2>/dev/null | head -n1)
trivy fs --scanners vuln,misconfig --severity HIGH,CRITICAL --skip-dirs node_modules --skip-dirs .git \
  --skip-dirs .scannerwork --skip-version-check --quiet --format json --output "$RAW" . 2>/tmp/trivy-run.log
RC=$?
if [ "$RC" -ne 0 ] || [ ! -s "$RAW" ]; then
  RES trivy trivy error --version "$VER" --detail "trivy exit $RC: $(tail -n2 /tmp/trivy-run.log | tr '\n' ' ')"; exit 0
fi
IMG_NOTE=""
for img in ${TRIVY_IMAGES:-}; do
  trivy image --severity HIGH,CRITICAL --skip-version-check --quiet --format json \
    --output "reports/raw/trivy-image-$(echo "$img" | tr '/:' '__').json" "$img" 2>>/tmp/trivy-run.log \
    || IMG_NOTE="$IMG_NOTE image-scan-failed:$img"
done
COUNTS=$(python3 - "$RAW" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); c = {"critical": 0, "high": 0}
for r in d.get("Results") or []:
    for item in (r.get("Vulnerabilities") or []) + (r.get("Misconfigurations") or []):
        s = str(item.get("Severity", "")).lower()
        if s in c: c[s] += 1
print(json.dumps(c))
PY
)
if [ -n "$IMG_NOTE" ]; then RES trivy trivy error --version "$VER" --raw "$RAW" --counts "$COUNTS" --detail "$IMG_NOTE"
else RES trivy trivy ok --version "$VER" --raw "$RAW" --counts "$COUNTS" --detail "fs scan${TRIVY_IMAGES:+ + images}"; fi
exit 0
