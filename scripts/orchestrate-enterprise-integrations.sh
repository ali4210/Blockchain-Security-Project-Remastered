#!/usr/bin/env bash
# Vault + Jenkins connectivity checks, with auto-heal re-seeding from a LOCAL,
# git-ignored seed file (never hardcoded in this script, never committed).
# Required env:  VAULT_TOKEN        (export it from your shell / a root-only env file)
# Optional env:  VAULT_ADDR, JENKINS_ADDR, VAULT_SEED_FILE (default: ~/.vault-seed.env)
# SonarQube moved to scripts/run-sonar.sh (scan, wait for the CE task, read the right gate).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
RES() { python3 scripts/lib/scanner_result.py "$@"; }
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
JENKINS_ADDR="${JENKINS_ADDR:-http://127.0.0.1:8082}"
SEED_FILE="${VAULT_SEED_FILE:-$HOME/.vault-seed.env}"
mkdir -p reports/scanners

# Load the local seed file (if present) -- this is the ONLY place real secret
# values may live, and it must never be inside the git repo.
if [ -f "$SEED_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$SEED_FILE"
  set +a
fi

echo "[+] ========================================================"
echo "[+] ENTERPRISE TOOLCHAIN CHECKS (Vault, Jenkins)"
echo "[+] ========================================================"

# Re-seed one Vault KV path from a JSON payload, only if it's currently empty.
# Never logs the payload itself.
seed_if_missing() {
  local path="$1" payload="$2" probe_field="$3"
  local current
  current=$(curl -s -m 5 -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/secret/data/${path}" \
            | jq -r ".data.data.${probe_field} // empty" 2>/dev/null)
  if [ -z "$current" ]; then
    echo "    [*] [VAULT AUTO-HEAL] Re-seeding secret/data/${path}..."
    curl -s -o /dev/null -X POST -H "X-Vault-Token: ${VAULT_TOKEN}" -H "Content-Type: application/json" \
      -d "$payload" "${VAULT_ADDR}/v1/secret/data/${path}"
  fi
}

echo "[+] [VAULT] Checking ${VAULT_ADDR}..."
if [ -z "${VAULT_TOKEN:-}" ]; then
  RES vault hashicorp-vault not_run --detail "VAULT_TOKEN not set in environment"
elif ! HEALTH=$(curl -s -m 5 "${VAULT_ADDR}/v1/sys/health") || [ -z "$HEALTH" ]; then
  RES vault hashicorp-vault error --detail "unreachable at ${VAULT_ADDR}"
elif ! echo "$HEALTH" | jq -e '.sealed == false' >/dev/null 2>&1; then
  RES vault hashicorp-vault error --detail "vault is sealed or health response invalid"
else
  curl -s -o /dev/null -m 5 -H "X-Vault-Token: ${VAULT_TOKEN}" -X POST "${VAULT_ADDR}/v1/sys/mounts/transit" -d '{"type":"transit"}' || true
  curl -s -o /dev/null -m 5 -H "X-Vault-Token: ${VAULT_TOKEN}" -X POST "${VAULT_ADDR}/v1/transit/keys/soc-relayer-key" -d '{"type":"ed25519"}' || true

  [ -n "${JENKINS_TOKEN:-}" ] && seed_if_missing jenkins \
    "{\"data\":{\"token\":\"${JENKINS_TOKEN}\",\"user\":\"${JENKINS_USER:-admin}\"}}" token
  [ -n "${SONARQUBE_TOKEN:-}" ] && seed_if_missing sonarqube \
    "{\"data\":{\"token\":\"${SONARQUBE_TOKEN}\"}}" token
  [ -n "${DEFECTDOJO_TOKEN:-}" ] && seed_if_missing defectdojo \
    "{\"data\":{\"token\":\"${DEFECTDOJO_TOKEN}\",\"url\":\"${DEFECTDOJO_URL:-http://127.0.0.1:8085}\"}}" token
  [ -n "${SLACK_WEBHOOK_URL:-}" ] && seed_if_missing slack \
    "{\"data\":{\"webhook_url\":\"${SLACK_WEBHOOK_URL}\"}}" webhook_url
  [ -n "${LANGFUSE_SECRET_KEY:-}" ] && seed_if_missing langfuse \
    "{\"data\":{\"public_key\":\"${LANGFUSE_PUBLIC_KEY:-}\",\"secret_key\":\"${LANGFUSE_SECRET_KEY}\",\"password\":\"${LANGFUSE_PASSWORD:-}\"}}" secret_key

  for p in jenkins sonarqube defectdojo slack langfuse; do
    if [ -z "$(curl -s -m 5 -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/secret/data/$p" | jq -r '.data.data | to_entries[0].value // empty')" ]; then
      echo "    [!] secret/data/$p is still empty. Add it to ${SEED_FILE} once, then rerun."
    fi
  done

  SIG=$(curl -s -m 5 -H "X-Vault-Token: ${VAULT_TOKEN}" -d '{"input": "YXV0b25vbW91cy1zb2MtcGlwZWxpbmUtYXR0ZXN0YXRpb24="}' \
        "${VAULT_ADDR}/v1/transit/sign/soc-relayer-key" | jq -r '.data.signature // empty')
  if [ -n "$SIG" ]; then RES vault hashicorp-vault ok --detail "healthy, unsealed; transit signing works (${SIG:0:24}...)"
  else RES vault hashicorp-vault error --detail "healthy but transit sign failed (token policy / key missing?)"; fi
fi

echo "[+] [JENKINS] Checking ${JENKINS_ADDR} (connectivity only)..."
JUSER="admin"; JTOKEN="${JENKINS_TOKEN:-}"
if [ -z "$JTOKEN" ] && [ -n "${VAULT_TOKEN:-}" ]; then
  JSEC=$(curl -s -m 5 -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/secret/data/jenkins")
  JTOKEN=$(echo "$JSEC" | jq -r '.data.data.token // empty'); JUSER=$(echo "$JSEC" | jq -r '.data.data.user // "admin"')
fi
if ! curl -fsS -m 5 -o /dev/null "${JENKINS_ADDR}/login"; then
  RES jenkins jenkins error --detail "unreachable at ${JENKINS_ADDR}"
elif [ -z "$JTOKEN" ]; then
  RES jenkins jenkins not_run --detail "no Jenkins token (JENKINS_TOKEN env or Vault secret/data/jenkins)"
else
  CRUMB=$(curl -s -m 8 -u "${JUSER}:${JTOKEN}" "${JENKINS_ADDR}/crumbIssuer/api/json" | jq -r '.crumbRequestField // empty')
  if [ -n "$CRUMB" ]; then RES jenkins jenkins ok --detail "authenticated (crumb ok); connectivity only: NO job is triggered by this script"
  else RES jenkins jenkins error --detail "authentication failed or crumb issuer disabled"; fi
fi
exit 0