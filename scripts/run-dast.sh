#!/usr/bin/env bash
# Zone 2.5: OWASP ZAP baseline against a REAL web target.
# Default: public-dashboard/ (what you actually publish) served on a throwaway local port.
# Override: DAST_TARGET=http://127.0.0.1:PORT   or   DAST_SERVE_DIR=some/dir
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
RES() { python3 scripts/lib/scanner_result.py "$@"; }
echo "[+] [ZONE 2.5] Running OWASP ZAP baseline DAST..."
mkdir -p reports/dast reports/scanners
rm -f reports/dast/zap-report.json reports/dast/zap-report.xml reports/dast/zap-report.html reports/zap-dast-report.xml
command -v docker >/dev/null 2>&1 || { RES zap zaproxy not_run --detail "docker not installed"; exit 0; }
TARGET="${DAST_TARGET:-}"
if [ -z "$TARGET" ]; then
  DIR="${DAST_SERVE_DIR:-public-dashboard}"; PORT="${DAST_PORT:-8099}"
  [ -d "$DIR" ] || { RES zap zaproxy error --detail "serve dir $DIR missing; set DAST_TARGET"; exit 0; }
  python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$DIR" >/tmp/dast-http.log 2>&1 &
  SRV=$!; trap 'kill $SRV 2>/dev/null' EXIT; sleep 1
  TARGET="http://127.0.0.1:$PORT"
fi
curl -fsS -m 5 -o /dev/null "$TARGET" || { RES zap zaproxy error --target "$TARGET" --detail "target not reachable"; exit 0; }
docker run --rm --network host -v "$PWD/reports/dast:/zap/wrk/:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$TARGET" -J zap-report.json -x zap-report.xml -r zap-report.html >/tmp/zap-exec.log 2>&1
RC=$?
# zap-baseline exit: 0 clean, 1 failures, 2 warnings, 3 error
if [ "$RC" -gt 2 ] || [ ! -s reports/dast/zap-report.json ]; then
  RES zap zaproxy error --target "$TARGET" --detail "zap exit $RC: $(tail -n2 /tmp/zap-exec.log | tr '\n' ' ')"; exit 0
fi
COUNTS=$(python3 - <<'PY'
import json
d = json.load(open("reports/dast/zap-report.json")); c = {"high": 0, "medium": 0, "low": 0, "info": 0}
names = {"3": "high", "2": "medium", "1": "low", "0": "info"}
for s in d.get("site", []):
    for a in s.get("alerts", []):
        c[names.get(str(a.get("riskcode")), "info")] += 1
print(json.dumps(c))
PY
)
RES zap zaproxy ok --target "$TARGET" --raw reports/dast/zap-report.json --counts "$COUNTS" --detail "baseline (passive) scan"
exit 0
