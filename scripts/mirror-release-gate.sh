#!/usr/bin/env bash
# Task P09-005: CLI wrapper for human-in-the-loop GitHub mirror gate
set -euo pipefail

TOKEN_FILE="${1:-}"

if [[ -z "$TOKEN_FILE" || ! -f "$TOKEN_FILE" ]]; then
  echo "[-] ERROR: Missing or unreadable human release token file." >&2
  echo "Usage: ./scripts/mirror-release-gate.sh <path-to-token.json>" >&2
  exit 1
fi

COMMIT_SHA=$(git rev-parse HEAD)

python3 -c "
import json, sys
from pathlib import Path
from src.mitigation.mirror_gate import MirrorReleaseGate
from src.mitigation.quarantine_staging import SignedReleaseToken

token_data = json.loads(Path('$TOKEN_FILE').read_text(encoding='utf-8'))
token = SignedReleaseToken(**token_data)

gate = MirrorReleaseGate()
try:
    gate.verify_token(token, '$COMMIT_SHA')
    print('[+] Human release token verified. Author: ' + token.operator_principal)
    sys.exit(0)
except Exception as e:
    print('[-] Denial: ' + str(e), file=sys.stderr)
    sys.exit(1)
"

echo "[+] Gate cleared. Synchronizing to GitHub origin..."
git push origin main
