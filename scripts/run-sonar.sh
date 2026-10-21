#!/usr/bin/env bash
# SonarQube: scan, WAIT for the compute-engine task, then read the gate of the SAME project key.
# (Old bug: scanner key was Blockchain-Security-Project-Remastered, gate query used blockchain-security-soc.)
# Token: SONAR_TOKEN env, else Vault secret/data/sonarqube (needs VAULT_TOKEN).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
RES() { python3 scripts/lib/scanner_result.py "$@"; }
SONAR_ADDR="${SONAR_ADDR:-http://127.0.0.1:9000}"
KEY="${SONAR_PROJECT_KEY:-Blockchain-Security-Project-Remastered}"
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
NOTE="Community Edition: Solidity not analysed; scripts only"
echo "[+] [SONARQUBE] Scan + quality gate for project $KEY..."
mkdir -p reports/scanners
curl -fsS -m 5 -o /dev/null "$SONAR_ADDR/api/system/status" || { RES sonar sonarqube error --detail "server unreachable at $SONAR_ADDR"; exit 0; }
if [ -z "${SONAR_TOKEN:-}" ] && [ -n "${VAULT_TOKEN:-}" ]; then
SONAR_TOKEN=$(curl -s -m 5 -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/secret/data/sonarqube" | jq -r '.data.data.token // empty')
fi
[ -n "${SONAR_TOKEN:-}" ] || { RES sonar sonarqube not_run --detail "no SONAR_TOKEN (env or Vault secret/data/sonarqube)"; exit 0; }
rm -f .scannerwork/report-task.txt
docker run --rm --network host -v "$PWD:/usr/src" sonarsource/sonar-scanner-cli \
-Dsonar.projectKey="$KEY" -Dsonar.projectName="$KEY" -Dsonar.sources=contracts,scripts \
-Dsonar.host.url="$SONAR_ADDR" -Dsonar.login="$SONAR_TOKEN" \
-Dsonar.working.directory=/usr/src/.scannerwork \
-Dsonar.python.coverage.reportPaths=/usr/src/coverage.xml \
-Dsonar.exclusions="out/**,cache/**,node_modules/**,lib/**,**/.git/**" >/tmp/sonar-scan.log 2>&1 \
|| { RES sonar sonarqube error --detail "scanner failed: $(tail -n2 /tmp/sonar-scan.log | tr '\n' ' ')"; exit 0; }
TASK_URL=$(sed -n 's/^ceTaskUrl=//p' .scannerwork/report-task.txt 2>/dev/null)
[ -n "$TASK_URL" ] || { RES sonar sonarqube error --detail "report-task.txt has no ceTaskUrl"; exit 0; }
ANALYSIS=""; STATE=""
for _ in $(seq 1 60); do
T=$(curl -s -m 10 -u "$SONAR_TOKEN:" "$TASK_URL")
STATE=$(echo "$T" | jq -r '.task.status // empty')
case "$STATE" in
SUCCESS) ANALYSIS=$(echo "$T" | jq -r '.task.analysisId'); break ;;
FAILED|CANCELED) RES sonar sonarqube error --detail "compute engine task $STATE"; exit 0 ;;
esac
sleep 2
done
[ -n "$ANALYSIS" ] || { RES sonar sonarqube error --detail "analysis not processed in time (last state: ${STATE:-none})"; exit 0; }
GATE=$(curl -s -m 10 -u "$SONAR_TOKEN:" "$SONAR_ADDR/api/qualitygates/project_status?analysisId=$ANALYSIS" | jq -r '.projectStatus.status // "UNKNOWN"')
if [ "$GATE" = "UNKNOWN" ]; then RES sonar sonarqube error --detail "gate status UNKNOWN for analysis $ANALYSIS"
else RES sonar sonarqube ok --detail "$NOTE" --extra "{\"gate\": \"$GATE\", \"project\": \"$KEY\"}"; fi
exit 0