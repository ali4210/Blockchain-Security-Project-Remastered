# Service / Port Source Dump

Generated for documentation accuracy. Every section below is either a verbatim
file (redactions marked explicitly) or raw command output, with its own
real-time cross-check in Part 3. Nothing here is a guessed or default port --
where no port is found anywhere in the repo for something referenced, that is
stated explicitly instead.

---

## Part 1 — Verbatim file contents

## 1a. docker-compose files (repo root + deploy/ + docker/)

### `docker-compose.yml`

```yaml
# TODO(phase-1/7): Hardened Live Deployment target (K8s is the eventual prod
# target per the blueprint — this compose file is the local dev/skeleton
# stand-in for Kali VM development before you wire up K8s + Vault KMS).
version: "3.9"
services:
  redis:
    image: redis:7
    ports: ["6379:6379"]
  # TODO(phase-4): add sqlite volume mount / init
  # TODO(phase-4): add mcp-middleware service
  # TODO(phase-9): add opa service running config/opa/agent_policy.rego
  # TODO(phase-10): evidence vault volume — read-only mount for sealed
  #   evidence, separate service account from the agent/mcp services
  # TODO(phase-10): add opa service running config/opa/forensics_policy.rego
  #   (can be the same OPA container as phase-9, loaded with both policies)
  # TODO(phase-11): consensus-monitor service — needs its own full/light
  #   node connection or indexer feed; runs continuously, independent of
  #   the CI pipeline
  # TODO(phase-12): HSM/MPC stand-in services for local dev (e.g. an HSM
  #   emulator container); never store real production keys here
  # TODO(phase-13): compliance-screen service — reuses the Zone 5 evidence
  #   vault's GraphSense integration on a schedule; add opa service loaded
  #   with config/opa/compliance_policy.rego too
```

### `docker-compose.test.yml`

```yaml
networks:
  mcp-test-network:
    driver: bridge

volumes:
  broker-data:
    driver: local
  forensics-data:
    driver: local

services:
  mcp-storage:
    image: python:3.12-slim
    container_name: mcp-storage-test
    user: "1000:1000"
    working_dir: /app
    volumes:
      - .:/app:ro
      - broker-data:/app/.broker_storage
    environment:
      - PYTHONUNBUFFERED=1
      - PYTHONDONTWRITEBYTECODE=1
    command: ["python3", "-c", "import time; print('MCP BrokerStore Storage Initialized in WAL mode'); time.sleep(3600)"]
    networks:
      - mcp-test-network
    deploy:
      resources:
        limits:
          cpus: "0.50"
          memory: 256M

  mcp-anvil:
    image: ghcr.io/foundry-rs/foundry:latest
    container_name: mcp-anvil-test
    user: "1000:1000"
    entrypoint: ["anvil"]
    command: ["--host", "0.0.0.0", "--port", "8545", "--silent"]
    ports:
      - "8545:8545"
    networks:
      - mcp-test-network
    deploy:
      resources:
        limits:
          cpus: "1.00"
          memory: 512M

  mcp-forensics:
    image: python:3.12-slim
    container_name: mcp-forensics-test
    user: "1000:1000"
    working_dir: /app
    volumes:
      - .:/app:ro
      - forensics-data:/mnt/evidence:ro
    environment:
      - PYTHONUNBUFFERED=1
      - PYTHONDONTWRITEBYTECODE=1
    command: ["python3", "-c", "import time; print('MCP Sleuth Kit Forensics Service (Read-Only) Ready'); time.sleep(3600)"]
    networks:
      - mcp-test-network
    deploy:
      resources:
        limits:
          cpus: "0.50"
          memory: 256M

  mcp-telemetry:
    image: python:3.12-slim
    container_name: mcp-telemetry-test
    user: "1000:1000"
    working_dir: /app
    volumes:
      - .:/app:ro
    environment:
      - PYTHONUNBUFFERED=1
      - PYTHONDONTWRITEBYTECODE=1
    command: ["python3", "-c", "import time; print('MCP Telemetry Prometheus/ELK Stubs Online'); time.sleep(3600)"]
    ports:
      - "9090:9090"
    networks:
      - mcp-test-network
    deploy:
      resources:
        limits:
          cpus: "0.50"
          memory: 256M
```

### `docker-compose.deploy.yml`

```yaml
version: "3.8"

services:
  testnet-rpc:
    image: ghcr.io/foundry-rs/foundry:latest
    container_name: bsp-testnet-rpc
    entrypoint: ["anvil"]
    command: ["--host", "0.0.0.0", "--port", "8545", "--chain-id", "31337"]
    ports:
      - "8545:8545"
    healthcheck:
      test: ["CMD-SHELL", "nc -z 127.0.0.1 8545 || exit 1"]
      interval: 3s
      timeout: 2s
      retries: 5

  consensus-deployer:
    image: python:3.11-slim
    container_name: bsp-consensus-deployer
    depends_on:
      testnet-rpc:
        condition: service_healthy
    volumes:
      - .:/workspace
    working_dir: /workspace
    environment:
      - RPC_URL=http://testnet-rpc:8545
      - PYTHONUNBUFFERED=1
    command: ["python3", "-c", "from src.deployment.consensus_deployer import ConsensusDeployer; print('Deployer simulation ready')"]
```

### `deploy/thehive/docker-compose.yml`

```yaml
services:
  thehive:
    image: thehiveproject/thehive4:4.1.24-1
    container_name: soc-thehive-enterprise
    restart: unless-stopped
    ports:
      - "9005:9000"
    environment:
      - JVM_OPTIONS=-Xms512m -Xmx1024m
    volumes:
      - ./conf/application.conf:/etc/thehive/application.conf:ro
      - ./data:/opt/thp/data
```

Also found outside root/deploy/, in `docker/` -- included for completeness since it's a real compose file with real ports ("nothing missed"):

### `docker/docker-compose.validators.yml`

```yaml
# Task P06-002: Three-Node Local AVS Validator Simulation Topology
# Educational Coursework Simulation — Not for Public Mainnet Deployment
services:
  validator-1:
    image: python:3.11-slim
    container_name: bsp_validator_1
    working_dir: /app
    volumes:
      - ..:/app:ro
    environment:
      - VALIDATOR_ID=validator-1
      - VALIDATOR_PORT=8081
      - PYTHONPATH=/app
    command: ["python3", "-m", "src.consensus.validator_node"]
    ports:
      - "8081:8081"
    networks:
      - avs-validator-net
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8081/health', timeout=2)"]
      interval: 5s
      timeout: 2s
      retries: 3
    restart: unless-stopped

  validator-2:
    image: python:3.11-slim
    container_name: bsp_validator_2
    working_dir: /app
    volumes:
      - ..:/app:ro
    environment:
      - VALIDATOR_ID=validator-2
      - VALIDATOR_PORT=8082
      - PYTHONPATH=/app
    command: ["python3", "-m", "src.consensus.validator_node"]
    ports:
      - "8082:8082"
    networks:
      - avs-validator-net
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8082/health', timeout=2)"]
      interval: 5s
      timeout: 2s
      retries: 3
    restart: unless-stopped

  validator-3:
    image: python:3.11-slim
    container_name: bsp_validator_3
    working_dir: /app
    volumes:
      - ..:/app:ro
    environment:
      - VALIDATOR_ID=validator-3
      - VALIDATOR_PORT=8083
      - PYTHONPATH=/app
    command: ["python3", "-m", "src.consensus.validator_node"]
    ports:
      - "8083:8083"
    networks:
      - avs-validator-net
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8083/health', timeout=2)"]
      interval: 5s
      timeout: 2s
      retries: 3
    restart: unless-stopped

networks:
  avs-validator-net:
    driver: bridge
```

## 1b. .env.example / non-secret .env files

No `.env.example` exists in this repo. `config/env.example` is the real
template file (genuinely non-secret -- all values blank except a default
local Ollama host/port) and is included in full:

### `config/env.example`

```bash
# ==============================================================================
# Blockchain Security Project Remastered — Local Environment Configuration
# Template file: DO NOT commit active credentials or private keys to git.
# Copy to .env.local (which is ignored by .gitignore) or export directly in shell.
# ==============================================================================

# Ollama Transport Bridge
# Set to local daemon, remote GPU host, or TLS reverse proxy
OLLAMA_HOST=http://127.0.0.1:11434

# HTTP Bearer Authentication Token (leave blank if authentication is disabled)
OLLAMA_BEARER_TOKEN=

# mTLS Client Authentication Certificates (leave blank if not using mTLS)
OLLAMA_CLIENT_CERT=
OLLAMA_CLIENT_KEY=
OLLAMA_CA_CERT=
```

The only other .env file is `.env` itself, which IS secret-bearing.
Tokens/passwords redacted below; variable names, the one real host value
(JIRA_URL), and structure are kept. **This file contains no host:port
values at all** -- every variable is a credential, identity, or SaaS URL,
not a local service endpoint:

### `.env` (redacted)

```bash
# === AUTONOMOUS BLOCKCHAIN SOC — LIVE JIRA CLOUD CONFIGURATION ===
JIRA_URL="https://saleemalimohammad211126.atlassian.net"
JIRA_USER="saleemali.mohammad211126@gmail.com"
JIRA_TOKEN="[REDACTED]"
JIRA_PROJECT_KEY="KAN"
VAULT_TOKEN="[REDACTED]"
THEHIVE_ORG="Blockchain-SOC"
ELASTIC_USER="elastic"
ELASTIC_PASSWORD="[REDACTED]"
SLACK_WEBHOOK_URL="[REDACTED -- webhook URL itself functions as a bearer secret]"
GMAIL_SENDER="saleemali.mohammad211126@gmail.com"
GMAIL_APP_PASSWORD="[REDACTED]"
GMAIL_RECEIVER="saleemali.mohammad@gmail.com"
```

## 1c. Other named files

### `scripts/orchestrate-enterprise-integrations.sh`

```bash
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

  # Jira lives at secret/data/soc/jira (not secret/data/<name> like the five
  # above), and its real credentials come from the project .env rather than
  # this seed file, so it re-seeds via the existing provisioning script
  # instead of an inline seed_if_missing payload. Its token is a static,
  # long-lived Atlassian API token (unlike TheHive's, which mints a new key
  # every provision run), so re-seeding it whenever empty carries no
  # stale-rotation risk -- same "only if missing" semantics as seed_if_missing.
  if [ -z "$(curl -s -m 5 -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/secret/data/soc/jira" | jq -r '.data.data.token // empty')" ]; then
    echo "    [*] [VAULT AUTO-HEAL] Re-seeding secret/data/soc/jira..."
    python3 scripts/provision-jira-vault.py >/dev/null 2>&1 \
      || echo "    [!] provision-jira-vault.py failed (JIRA_URL/JIRA_USER/JIRA_TOKEN missing from .env?)"
  fi

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
```

### `config/telemetry/prometheus.blockchain-soc.yml`

```yaml
# Blockchain SOC Scrape Targets for Host-Mode Prometheus
#
# Reconciled against the live running Prometheus container's actual config
# (confirmed via its own /api/v1/status/config, not guessed): the real
# deployment is driven by /srv/devsecops/prometheus/prometheus.yml on the
# host, outside this repo, and had drifted from what's checked in here --
# different job names, different target counts, and a dead "cross-node-
# exporter:9100" target with no DNS record anywhere reachable from this
# host. This file now matches the real, reachable targets so it stops being
# stale documentation of infrastructure that no longer exists.
global:
  scrape_interval: 5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: "node_exporter"
    static_configs:
      # "cross-node-exporter:9100" removed: no DNS record resolves it from
      # this host (confirmed live: dial tcp: lookup cross-node-exporter on
      # 8.8.8.8:53: no such host). localhost:9100 and 172.17.0.1:9100 are
      # both confirmed reachable and serving real node_exporter metrics.
      - targets: ["localhost:9100", "172.17.0.1:9100"]

  - job_name: "blockchain-soc-metrics"
    static_configs:
      # The real pipeline exporter (scripts/ship-siem-telemetry.py's HTTP
      # server), confirmed reachable and serving real per-run metrics.
      - targets: ["172.17.0.1:9101"]
    metrics_path: "/metrics"
```

### `config/grafana-soc-v10-4-dashboard.json` (first 50 lines only, per instruction)

```json
{
  "annotations": { "list": [] },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 1,
  "id": null,
  "links": [],
  "liveNow": true,
  "panels": [
    {
      "collapsed": false,
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 0 },
      "id": 100,
      "title": "Autonomous Blockchain SOC — Executive Key Performance Indicators",
      "type": "row"
    },
    {
      "datasource": { "type": "prometheus", "uid": "prometheus-default" },
      "fieldConfig": {
        "defaults": {
          "color": { "mode": "thresholds" },
          "mappings": [
            { "options": { "0": { "color": "red", "text": "PIPELINE FAILED" }, "1": { "color": "green", "text": "100% OPERATIONAL" } }, "type": "value" }
          ],
          "thresholds": { "mode": "absolute", "steps": [{ "color": "red", "value": null }, { "color": "green", "value": 1 }] }
        }
      },
      "gridPos": { "h": 4, "w": 4, "x": 0, "y": 1 },
      "id": 1,
      "options": { "colorMode": "background", "graphMode": "none", "justifyMode": "center", "orientation": "auto", "reduceOptions": { "calcs": ["lastNotNull"], "fields": "", "values": false }, "textMode": "auto" },
      "targets": [{ "datasource": { "type": "prometheus", "uid": "prometheus-default" }, "expr": "max(blockchain_soc_pipeline_success)", "format": "time_series", "instant": true, "refId": "A" }],
      "title": "Pipeline Execution Gate",
      "type": "stat"
    },
    {
      "datasource": { "type": "prometheus", "uid": "prometheus-default" },
      "fieldConfig": {
        "defaults": {
          "color": { "mode": "thresholds" },
          "max": 10,
          "min": 0,
          "thresholds": { "mode": "absolute", "steps": [{ "color": "green", "value": null }, { "color": "#EAB839", "value": 4 }, { "color": "red", "value": 7 }] }
        }
      },
      "gridPos": { "h": 4, "w": 5, "x": 4, "y": 1 },
      "id": 2,
      "options": { "orientation": "auto", "reduceOptions": { "calcs": ["lastNotNull"], "fields": "", "values": false }, "showThresholdLabels": false, "showThresholdMarkers": true },
      "targets": [{ "datasource": { "type": "prometheus", "uid": "prometheus-default" }, "expr": "max(blockchain_soc_dread_score)", "format": "time_series", "instant": true, "refId": "A" }],
      "title": "DREAD Risk Score (Max 10)",
      "type": "gauge"
```

**Port/datasource-url fields in the full 498-line file:** none. Every panel's
`datasource` field is `{ "type": "prometheus", "uid": "prometheus-default" }`
-- a UID reference resolved by Grafana's own datasource provisioning, not a
literal URL or port anywhere in this JSON. (Grafana's real Prometheus
datasource connection -- host/port -- is configured at the Grafana server
level, outside this dashboard file, and outside what was asked to be dumped
here.) Grepped all 498 lines for "port"/"url" case-insensitively to confirm
-- zero matches beyond the UID pattern above.

### `dashboard/README.md`

```markdown
# TODO(phase-10): Next.js/Vercel live SOC dashboard — see checklist Phase 10
```

### `public-dashboard/index.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Blockchain Security Swarm — Unified Executive Report</title>
  <style>
    :root {
      --bg-primary: #0b0f17;
      --bg-secondary: #111827;
      --bg-card: #162032;
      --border-color: #243247;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg-primary);
      color: var(--text-main);
      font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding: 30px;
    }
    .container { max-width: 1350px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 20px;
      margin-bottom: 30px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    h1 { font-size: 24px; font-weight: 700; color: #fff; }
    .meta { font-size: 13px; color: var(--text-muted); margin-top: 5px; }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 30px;
    }
    .kpi-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
    }
    .kpi-title { font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
    .kpi-value { font-size: 26px; font-weight: 700; margin-top: 6px; color: #fff; }
    .section-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 22px;
      margin-bottom: 28px;
    }
    .section-title { font-size: 17px; font-weight: 600; margin-bottom: 14px; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th { text-align: left; padding: 10px 12px; font-size: 11px; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border-color); }
    td { padding: 12px; font-size: 13px; border-bottom: 1px solid #1a2538; vertical-align: top; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .toolbar { display: flex; gap: 12px; margin-bottom: 15px; }
    .search-input {
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      color: #fff;
      padding: 8px 14px;
      font-size: 13px;
      width: 320px;
    }
    .btn {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 13px;
      cursor: pointer;
    }
    .btn:hover { background: #1e2c45; }
    .takeaway-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }
    .takeaway-box { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 16px; font-size: 13px; }
    @media print {
      body { background: #fff; color: #000; padding: 0; }
      .section-card, .kpi-card, .takeaway-box { border: 1px solid #ccc; background: #fff; color: #000; }
      .toolbar { display: none; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Blockchain Security Swarm — Unified Executive Report</h1>
        <div class="meta">Generated: 2026-10-13T08:03:56.381Z | Commit: <code>cffbdfbeef</code> | Release: 1.0.0-phase14</div>
      </div>
      <div>
        <button class="btn" onclick="window.print()">Print / Export PDF</button>
      </div>
    </header>

    <!-- Executive KPI Cards -->
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-title">Total Active Findings</div>
        <div class="kpi-value">6</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Critical & High Flaws</div>
        <div class="kpi-value" style="color: #ef4444;">4</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Compliance Pass Rate</div>
        <div class="kpi-value" style="color: #22c55e;">100%</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Consensus Alerts</div>
        <div class="kpi-value">1</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Sealed Forensic Cases</div>
        <div class="kpi-value">3</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Benchmark F1 Score</div>
        <div class="kpi-value" style="color: #38bdf8;">0.988</div>
      </div>
    </div>

    <!-- Templated Executive Takeaways -->
    <div class="section-card">
      <div class="section-title">Automated Executive Synthesis & Action Posture</div>
      <div class="takeaway-grid">
        <div class="takeaway-box">
          <b style="color: #22c55e;">Systemic Strengths & Active Safeguards</b>
          <ul style="margin-top: 8px; padding-left: 18px; color: #cbd5e1;">
            <li>Zero-Knowledge Pedersen commitments verify compliance without exposing transaction trails.</li>
            <li>Fail-closed relayer quarantine prevents balance drains during reentrancy exploits.</li>
            <li>Immutable OPA guardrails universally block autonomous filing and transaction censorship.</li>
          </ul>
        </div>
        <div class="takeaway-box">
          <b style="color: #f97316;">Identified Flaws & Vulnerabilities</b>
          <ul style="margin-top: 8px; padding-left: 18px; color: #cbd5e1;">
            <li><b>FIND-Z6-001</b>: Subnet Clustering Anomaly (HIGH)</li>
          </ul>
        </div>
        <div class="takeaway-box">
          <b style="color: #38bdf8;">Recommended Actions</b>
          <ul style="margin-top: 8px; padding-left: 18px; color: #cbd5e1;">
            <li>Perform re-screening of P2P autonomous system numbers to expand geographic peer diversity.</li>
            <li>Initiate scheduled human-in-the-loop signoff for staged draft SAR candidate records.</li>
            <li>Maintain daily regression sweeps against the multi-zone integration battery.</li>
          </ul>
        </div>
      </div>
    </div>

    <!-- Zone 6: Consensus Attack & Alert Timeline Panel -->
    <div class="section-card">
      <div class="section-title">Zone 6: Consensus Attack Monitoring & Alert Timeline</div>
      
    <div style="position:relative; padding-left: 20px; border-left: 2px solid #334155; margin: 15px 0;">
      
        <div style="margin-bottom: 12px; position:relative;">
          <div style="position:absolute; left:-27px; top:4px; width:12px; height:12px; border-radius:50%; background:#f97316; border:2px solid #0f172a;"></div>
          <div style="font-size:13px; font-weight:600; color:#f8fafc;">SELFISH_MINING_PRIVATE_FORK —<span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #f97316; background: rgba(249, 115, 22, 0.15); border: 1px solid rgba(249, 115, 22, 0.4);">HIGH</span></div>
          <div style="font-size:11px; color:#94a3b8; margin-top:2px;">
            <span>ID: <code>ALERT-CN-101</code></span> | 
            <span>AVS Quorum: <b><span style='color:#22c55e;'>VERIFIED (2/3+)</span></b></span> | 
            <span>Time: 2026-10-12T20:15:00Z</span>
          </div>
        </div>
      
    </div>
  
    </div>

    <!-- Zone 7: Wallet Audit & Key Scheme Posture -->
    <div class="section-card">
      <div class="section-title">Zone 7: Wallet Audit & Key-Scheme Posture</div>
      <table>
        <thead>
          <tr>
            <th>Audit ID</th>
            <th>Vulnerability Classification</th>
            <th>Cryptographic Scheme</th>
            <th>Post-Audit Status</th>
          </tr>
        </thead>
        <tbody>
          
    <tr>
      <td style="font-family:monospace; font-size:12px;">WAL-AUD-01</td>
      <td><b>REENTRANCY_EXTERNAL_CALL</b></td>
      <td><span style="font-size:11px; background:#1e293b; color:#a78bfa; padding:2px 8px; border-radius:4px; font-weight:600;">MPC_3_OF_5_THRESHOLD</span></td>
      <td><span style="font-size:11px; font-weight:700; color:#22c55e;">MITIGATED</span></td>
    </tr>
  
    <tr>
      <td style="font-family:monospace; font-size:12px;">WAL-AUD-02</td>
      <td><b>MISSING_PRESIGN_SIMULATION</b></td>
      <td><span style="font-size:11px; background:#1e293b; color:#a78bfa; padding:2px 8px; border-radius:4px; font-weight:600;">HSM_PKCS11_EMULATED</span></td>
      <td><span style="font-size:11px; font-weight:700; color:#22c55e;">PASS</span></td>
    </tr>
  
        </tbody>
      </table>
    </div>

    <!-- Zone 5: Forensic Case Timeline -->
    <div class="section-card">
      <div class="section-title">Zone 5: Forensic Cases & Chain of Custody (Redacted Summaries)</div>
      <table>
        <thead>
          <tr>
            <th>Case Identifier</th>
            <th>Target Address</th>
            <th>Sealed Artifacts</th>
            <th>Custody Integrity</th>
            <th>Sanitized Summary</th>
          </tr>
        </thead>
        <tbody>
          
    <tr>
      <td style="font-family:monospace; font-size:12px;">CASE-FR-001</td>
      <td style="font-family:monospace; font-size:11px; color:#93c5fd;">0x098b716b8aaf21512996dc57eb0615e2383e2f96</td>
      <td style="font-family:monospace;">4 artifacts</td>
      <td><span style="color:#22c55e; font-weight:700;">VALID (SHA-256 LOCKED)</span></td>
      <td style="font-size:12px; color:#94a3b8;">Volatile memory and state logs captured strictly in volatility sequence; sha256 manifests locked.</td>
    </tr>
  
        </tbody>
      </table>
    </div>

    <!-- Zone 8: Compliance Register -->
    <div class="section-card">
      <div class="section-title">Zone 8: Regulatory Compliance Register & Sanctions Screening</div>
      <table>
        <thead>
          <tr>
            <th>Counterparty Address</th>
            <th>Sanction Status</th>
            <th>Assessed Tier</th>
            <th>AML Signals</th>
            <th>ZK Attestation Status</th>
            <th>HITL Staging Gate</th>
          </tr>
        </thead>
        <tbody>
          
    <tr>
      <td style="font-family:monospace; font-size:11px; color:#cbd5e1;">0xd90e2f925da726b50c4ed8d0fb90ad053324f31b</td>
      <td><span style="font-size:11px; font-weight:700; color:#ef4444;">SDN MATCH</span></td>
      <td><span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #94a3b8; background: rgba(148, 163, 184, 0.15); border: 1px solid rgba(148, 163, 184, 0.4);">CRITICAL_SANCTIONED</span></td>
      <td style="font-family:monospace;">2 signals</td>
      <td><span style="font-size:11px; font-weight:600; color:#38bdf8;">ZK-VERIFIED (PEDERSEN)</span></td>
      <td><span style="font-size:11px; background:rgba(234, 179, 8, 0.15); color:#eab308; padding:2px 6px; border-radius:4px; font-weight:600;">DRAFT_PENDING_REVIEW</span></td>
    </tr>
  
        </tbody>
      </table>
    </div>

    <!-- Severity Distribution & Verification Health -->
    <div class="section-card">
      <div class="section-title">Severity Breakdown & Verification Matrix</div>
      
    <div style="display:flex; align-items:center; gap:20px;">
      <svg width="120" height="120" viewBox="0 0 42 42" style="transform: rotate(-90deg);">
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#1e293b" stroke-width="5"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#ef4444" stroke-width="5" stroke-dasharray="33.33333333333333 66.66666666666667" stroke-dashoffset="0"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#f97316" stroke-width="5" stroke-dasharray="33.33333333333333 66.66666666666667" stroke-dashoffset="-33.33333333333333"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#eab308" stroke-width="5" stroke-dasharray="16.666666666666664 83.33333333333334" stroke-dashoffset="-66.66666666666666"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#3b82f6" stroke-width="5" stroke-dasharray="16.666666666666664 83.33333333333334" stroke-dashoffset="-83.33333333333331"></circle>
      </svg>
      <div style="font-size: 12px; display:flex; flex-direction:column; gap:6px;">
        <div><span style="color:#ef4444">■</span> Critical: <b>2</b></div>
        <div><span style="color:#f97316">■</span> High: <b>2</b></div>
        <div><span style="color:#eab308">■</span> Medium: <b>1</b></div>
        <div><span style="color:#3b82f6">■</span> Low: <b>1</b></div>
      </div>
    </div>
  
      <table style="margin-top: 20px;">
        <thead>
          <tr>
            <th>Security Zone</th>
            <th>Verification Status</th>
            <th>Automated Tests</th>
            <th>Scope Description</th>
          </tr>
        </thead>
        <tbody>
          
    <tr>
      <td><b>ZONE_1_CONTRACTS</b></td>
      <td><span style="color:#22c55e; font-weight:700;">● PASS</span></td>
      <td style="font-family:monospace;">85 tests</td>
      <td style="color:#94a3b8; font-size:12px;">Hardhat &amp; Foundry unit suites verified.</td>
    </tr>
  
    <tr>
      <td><b>ZONE_2_FORENSICS</b></td>
      <td><span style="color:#22c55e; font-weight:700;">● PASS</span></td>
      <td style="font-family:monospace;">50 tests</td>
      <td style="color:#94a3b8; font-size:12px;">Sealed evidence and volatile chain valid.</td>
    </tr>
  
    <tr>
      <td><b>ZONE_3_AGENTS</b></td>
      <td><span style="color:#22c55e; font-weight:700;">● PASS</span></td>
      <td style="font-family:monospace;">42 tests</td>
      <td style="color:#94a3b8; font-size:12px;">Multi-agent LangGraph workflow coordinated.</td>
    </tr>
  
    <tr>
      <td><b>ZONE_6_CONSENSUS</b></td>
      <td><span style="color:#22c55e; font-weight:700;">● PASS</span></td>
      <td style="font-family:monospace;">99 tests</td>
      <td style="color:#94a3b8; font-size:12px;">Supermajority and BLS aggregation active.</td>
    </tr>
  
    <tr>
      <td><b>ZONE_7_WALLET</b></td>
      <td><span style="color:#22c55e; font-weight:700;">● PASS</span></td>
      <td style="font-family:monospace;">56 tests</td>
      <td style="color:#94a3b8; font-size:12px;">Shamir key recovery and HSM emulator intact.</td>
    </tr>
  
    <tr>
      <td><b>ZONE_8_COMPLIANCE</b></td>
      <td><span style="color:#22c55e; font-weight:700;">● PASS</span></td>
      <td style="font-family:monospace;">55 tests</td>
      <td style="color:#94a3b8; font-size:12px;">Sanctions screening and ZK attestations verified.</td>
    </tr>
  
    <tr>
      <td><b>ZONE_9_MITIGATION</b></td>
      <td><span style="color:#22c55e; font-weight:700;">● PASS</span></td>
      <td style="font-family:monospace;">26 tests</td>
      <td style="color:#94a3b8; font-size:12px;">Release gate and egress isolation locked.</td>
    </tr>
  
    <tr>
      <td><b>ZONE_10_MIDDLEWARE</b></td>
      <td><span style="color:#22c55e; font-weight:700;">● PASS</span></td>
      <td style="font-family:monospace;">26 tests</td>
      <td style="color:#94a3b8; font-size:12px;">MCP tools and rate limiting active.</td>
    </tr>
  
        </tbody>
      </table>
    </div>

    <!-- Findings & Flaws Interactive Table -->
    <div class="section-card">
      <div class="section-title">Master Security Findings Register</div>
      <div class="toolbar">
        <input type="text" id="findingSearch" class="search-input" placeholder="Live search title, rule, target..." onkeyup="filterFindings()">
      </div>
      <table id="findingsTable">
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Zone</th>
            <th>Finding & Details</th>
            <th>Target Context</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          
    <tr>
      <td style="font-family:monospace; font-size:12px;">FIND-Z1-001</td>
      <td><span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #ef4444; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4);">CRITICAL</span></td>
      <td><span style="font-size:11px; background:#1e293b; padding:2px 6px; border-radius:4px;">ZONE_1_CONTRACTS</span></td>
      <td><b>Reentrancy in VulnerableVault.sol</b><div style="font-size:12px; color:#94a3b8; margin-top:2px;">State balance mutation occurs after low-level external ether transfer call.</div></td>
      <td style="font-family:monospace; font-size:11px; color:#cbd5e1;">contracts/solidity/VulnerableVault.sol</td>
      <td><span style="font-size:11px; font-weight:600; color:#38bdf8;">MITIGATED</span></td>
    </tr>
  
    <tr>
      <td style="font-family:monospace; font-size:12px;">FIND-Z8-001</td>
      <td><span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #ef4444; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4);">CRITICAL</span></td>
      <td><span style="font-size:11px; background:#1e293b; padding:2px 6px; border-radius:4px;">ZONE_8_COMPLIANCE</span></td>
      <td><b>Sanctioned Counterparty Identified</b><div style="font-size:12px; color:#94a3b8; margin-top:2px;">Address match against OFAC SDN Tornado Cash router.</div></td>
      <td style="font-family:monospace; font-size:11px; color:#cbd5e1;">0xd90e2f925da726b50c4ed8d0fb90ad053324f31b</td>
      <td><span style="font-size:11px; font-weight:600; color:#38bdf8;">VERIFIED</span></td>
    </tr>
  
    <tr>
      <td style="font-family:monospace; font-size:12px;">FIND-Z6-001</td>
      <td><span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #f97316; background: rgba(249, 115, 22, 0.15); border: 1px solid rgba(249, 115, 22, 0.4);">HIGH</span></td>
      <td><span style="font-size:11px; background:#1e293b; padding:2px 6px; border-radius:4px;">ZONE_6_CONSENSUS</span></td>
      <td><b>Subnet Clustering Anomaly</b><div style="font-size:12px; color:#94a3b8; margin-top:2px;">Peer table exhibits ASN clustering indicating potential eclipse attempt.</div></td>
      <td style="font-family:monospace; font-size:11px; color:#cbd5e1;">P2P Peer Table</td>
      <td><span style="font-size:11px; font-weight:600; color:#38bdf8;">OPEN</span></td>
    </tr>
  
    <tr>
      <td style="font-family:monospace; font-size:12px;">FIND-Z7-001</td>
      <td><span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #f97316; background: rgba(249, 115, 22, 0.15); border: 1px solid rgba(249, 115, 22, 0.4);">HIGH</span></td>
      <td><span style="font-size:11px; background:#1e293b; padding:2px 6px; border-radius:4px;">ZONE_7_WALLET</span></td>
      <td><b>Simulation Exceeds Balance Drain Threshold</b><div style="font-size:12px; color:#94a3b8; margin-top:2px;">Pre-sign transaction simulator triggered fail-closed isolation gate.</div></td>
      <td style="font-family:monospace; font-size:11px; color:#cbd5e1;">Relayer Multisig Safe</td>
      <td><span style="font-size:11px; font-weight:600; color:#38bdf8;">MITIGATED</span></td>
    </tr>
  
    <tr>
      <td style="font-family:monospace; font-size:12px;">FIND-Z5-001</td>
      <td><span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #eab308; background: rgba(234, 179, 8, 0.15); border: 1px solid rgba(234, 179, 8, 0.4);">MEDIUM</span></td>
      <td><span style="font-size:11px; background:#1e293b; padding:2px 6px; border-radius:4px;">ZONE_5_FORENSICS</span></td>
      <td><b>Unlinked Working Copy Corrupted</b><div style="font-size:12px; color:#94a3b8; margin-top:2px;">Cryptographic hash verification detected uncommitted single-byte variation.</div></td>
      <td style="font-family:monospace; font-size:11px; color:#cbd5e1;">Evidence Vault Replica</td>
      <td><span style="font-size:11px; font-weight:600; color:#38bdf8;">VERIFIED</span></td>
    </tr>
  
    <tr>
      <td style="font-family:monospace; font-size:12px;">FIND-Z8-002</td>
      <td><span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #3b82f6; background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.4);">LOW</span></td>
      <td><span style="font-size:11px; background:#1e293b; padding:2px 6px; border-radius:4px;">ZONE_8_COMPLIANCE</span></td>
      <td><b>Rapid Layering Chain Detected</b><div style="font-size:12px; color:#94a3b8; margin-top:2px;">Transfers occurred across 3 ephemeral addresses with sub-60s holding periods.</div></td>
      <td style="font-family:monospace; font-size:11px; color:#cbd5e1;">0x1111111111111111111111111111111111111111</td>
      <td><span style="font-size:11px; font-weight:600; color:#38bdf8;">ACKNOWLEDGED</span></td>
    </tr>
  
        </tbody>
      </table>
    </div>
  </div>

  <script>
    function filterFindings() {
      const input = document.getElementById("findingSearch");
      const filter = input.value.toLowerCase();
      const rows = document.querySelectorAll("#findingsTable tbody tr");
      for (const row of rows) {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(filter) ? "" : "none";
      }
    }
  </script>
</body>
</html>
```

### `public-dashboard/status.json`

```json
{
  "schemaVersion": 1,
  "timestamp": "2026-10-13T08:03:56.381Z",
  "system": {
    "name": "Blockchain Security Swarm",
    "version": "1.0.0-phase14",
    "commitSha": "cffbdfbeef2dde4bd99f572216905cecba362e62",
    "status": "HEALTHY"
  },
  "metrics": {
    "totalFindings": 6,
    "criticalFindings": 2,
    "highFindings": 2,
    "mediumFindings": 1,
    "lowFindings": 1,
    "complianceScorePct": 100,
    "activeConsensusAlerts": 0,
    "forensicCasesSealed": 3
  },
  "findings": [
    {
      "id": "FIND-Z1-001",
      "rule_id": "SWC-107",
      "zone": "ZONE_1_CONTRACTS",
      "severity": "CRITICAL",
      "title": "Reentrancy in VulnerableVault.sol",
      "description": "State balance mutation occurs after low-level external ether transfer call.",
      "target": "contracts/solidity/VulnerableVault.sol",
      "status": "MITIGATED"
    },
    {
      "id": "FIND-Z8-001",
      "rule_id": "RULE-SANCTIONS-HIT",
      "zone": "ZONE_8_COMPLIANCE",
      "severity": "CRITICAL",
      "title": "Sanctioned Counterparty Identified",
      "description": "Address match against OFAC SDN Tornado Cash router.",
      "target": "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
      "status": "VERIFIED"
    },
    {
      "id": "FIND-Z6-001",
      "rule_id": "RULE-CONSENSUS-ECLIPSE",
      "zone": "ZONE_6_CONSENSUS",
      "severity": "HIGH",
      "title": "Subnet Clustering Anomaly",
      "description": "Peer table exhibits ASN clustering indicating potential eclipse attempt.",
      "target": "P2P Peer Table",
      "status": "OPEN"
    },
    {
      "id": "FIND-Z7-001",
      "rule_id": "RULE-WALLET-DRAIN",
      "zone": "ZONE_7_WALLET",
      "severity": "HIGH",
      "title": "Simulation Exceeds Balance Drain Threshold",
      "description": "Pre-sign transaction simulator triggered fail-closed isolation gate.",
      "target": "Relayer Multisig Safe",
      "status": "MITIGATED"
    },
    {
      "id": "FIND-Z5-001",
      "rule_id": "RULE-HOST-TAMPER",
      "zone": "ZONE_5_FORENSICS",
      "severity": "MEDIUM",
      "title": "Unlinked Working Copy Corrupted",
      "description": "Cryptographic hash verification detected uncommitted single-byte variation.",
      "target": "Evidence Vault Replica",
      "status": "VERIFIED"
    },
    {
      "id": "FIND-Z8-002",
      "rule_id": "RULE-AML-STRUCTURING",
      "zone": "ZONE_8_COMPLIANCE",
      "severity": "LOW",
      "title": "Rapid Layering Chain Detected",
      "description": "Transfers occurred across 3 ephemeral addresses with sub-60s holding periods.",
      "target": "0x1111111111111111111111111111111111111111",
      "status": "ACKNOWLEDGED"
    }
  ],
  "incidents": [
    {
      "id": "INC-2026-001",
      "title": "Automated Relayer Quarantine on Balance Drain Simulation",
      "severity": "CRITICAL",
      "status": "CONTAINED",
      "createdAt": "2026-10-12T14:32:00Z"
    },
    {
      "id": "INC-2026-002",
      "title": "Peer Table Rebalancing After ASN Monopolization Alert",
      "severity": "HIGH",
      "status": "RESOLVED",
      "createdAt": "2026-10-12T18:10:00Z"
    }
  ],
  "forensicCases": [
    {
      "caseId": "CASE-FR-001",
      "targetAddress": "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
      "sealedArtifactsCount": 4,
      "integrityVerified": true,
      "redactedSummary": "Volatile memory and state logs captured strictly in volatility sequence; sha256 manifests locked."
    }
  ],
  "consensusAlerts": [
    {
      "alertId": "ALERT-CN-101",
      "anomalyType": "SELFISH_MINING_PRIVATE_FORK",
      "severity": "HIGH",
      "avsQuorumConfirmed": true,
      "timestamp": "2026-10-12T20:15:00Z"
    }
  ],
  "walletAuditFindings": [
    {
      "findingId": "WAL-AUD-01",
      "vulnerabilityClass": "REENTRANCY_EXTERNAL_CALL",
      "keyScheme": "MPC_3_OF_5_THRESHOLD",
      "status": "MITIGATED"
    },
    {
      "findingId": "WAL-AUD-02",
      "vulnerabilityClass": "MISSING_PRESIGN_SIMULATION",
      "keyScheme": "HSM_PKCS11_EMULATED",
      "status": "PASS"
    }
  ],
  "complianceRegister": [
    {
      "entityAddress": "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
      "sanctionMatch": true,
      "riskTier": "CRITICAL_SANCTIONED",
      "amlSignalsCount": 2,
      "zkProofVerified": true,
      "hitlStatus": "DRAFT_PENDING_REVIEW"
    }
  ],
  "benchmarks": {
    "precision": 0.985,
    "recall": 0.992,
    "f1Score": 0.988,
    "meanDetectionLatencyMs": 42.4
  },
  "mlResults": {
    "confusionMatrix": {
      "tp": 184,
      "fp": 2,
      "tn": 340,
      "fn": 1
    }
  },
  "zones": {
    "ZONE_1_CONTRACTS": {
      "status": "PASS",
      "testCount": 85,
      "summary": "Hardhat & Foundry unit suites verified."
    },
    "ZONE_2_FORENSICS": {
      "status": "PASS",
      "testCount": 50,
      "summary": "Sealed evidence and volatile chain valid."
    },
    "ZONE_3_AGENTS": {
      "status": "PASS",
      "testCount": 42,
      "summary": "Multi-agent LangGraph workflow coordinated."
    },
    "ZONE_6_CONSENSUS": {
      "status": "PASS",
      "testCount": 99,
      "summary": "Supermajority and BLS aggregation active."
    },
    "ZONE_7_WALLET": {
      "status": "PASS",
      "testCount": 56,
      "summary": "Shamir key recovery and HSM emulator intact."
    },
    "ZONE_8_COMPLIANCE": {
      "status": "PASS",
      "testCount": 55,
      "summary": "Sanctions screening and ZK attestations verified."
    },
    "ZONE_9_MITIGATION": {
      "status": "PASS",
      "testCount": 26,
      "summary": "Release gate and egress isolation locked."
    },
    "ZONE_10_MIDDLEWARE": {
      "status": "PASS",
      "testCount": 26,
      "summary": "MCP tools and rate limiting active."
    }
  }
}
```

### `public-dashboard/vercel.json`

```json
{
  "cleanUrls": true,
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        }
      ]
    }
  ]
}
```

---

## Part 2 — Repo-wide grep sweep for port patterns

Two passes, both excluding `node_modules`, `.git`, `.venv`, `venv`, `artifacts`,
`cache`, `out`, lockfiles.

### 2a. Exact patterns as specified (`:8xxx`, `:9xxx`, `:3xxx`, `:5xxx`,
`localhost:`, `127.0.0.1:`, `0.0.0.0:`)

```
Jenkinsfile:5:        VAULT_ADDR = 'http://192.168.0.150:8200'
Jenkinsfile:29:                      -Dsonar.host.url="http://127.0.0.1:9000" \
docker-compose.deploy.yml:10:      - "8545:8545"
docker-compose.deploy.yml:27:      - RPC_URL=http://testnet-rpc:8545
.gitlab-ci.yml:8:  VAULT_ADDR: "http://172.17.0.1:8200"
.gitlab-ci.yml:10:  JENKINS_ADDR: "http://172.17.0.1:8082"
docs/OBSERVABILITY_STACK.md:10:| **Prometheus** | `9090` | host | `cross-prometheus` (v2.51.0) | Metric collection from agents, AVS, RASP (`:9100-9102`) |
docs/OBSERVABILITY_STACK.md:19:- **Metrics Endpoint**: `http://localhost:9090/metrics`
docs/OBSERVABILITY_STACK.md:25:- **Metrics Endpoint**: `http://localhost:9090`
docs/OBSERVABILITY_STACK.md:26:- **Dashboard Service**: `http://localhost:3000`
docs/architecture/VALIDATOR_SIMULATION.md:30:curl -s http://localhost:8081/health | jq .
docs/architecture/VALIDATOR_SIMULATION.md:31:curl -s http://localhost:8082/health | jq .
docs/architecture/VALIDATOR_SIMULATION.md:32:curl -s http://localhost:8083/health | jq .
test/observability/test_telemetry_stack.py:23:        self.assertEqual(ep.url, "http://127.0.0.1:9090/metrics")
test/observability/test_telemetry_stack.py:83:            url="http://localhost:9200/",
docker-compose.test.yml:39:      - "8545:8545"
docker-compose.test.yml:80:      - "9090:9090"
scripts/ingest-thehive-incident.py:22:THEHIVE_BASE = os.environ.get("THEHIVE_BASE", os.environ.get("THEHIVE_URL", "http://127.0.0.1:9005"))
scripts/ingest-thehive-incident.py:24:VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/langfuse_tracer.py:48:    host = env.get("LANGFUSE_HOST", "http://127.0.0.1:3100")
config/env.example:9:OLLAMA_HOST=http://127.0.0.1:11434
test/consensus/test_validator_cluster.py:35:        url = f"http://127.0.0.1:{self.port}/health"
test/consensus/test_validator_cluster.py:44:        url = f"http://127.0.0.1:{self.port}/vote"
test/consensus/test_validator_cluster.py:60:        url = f"http://127.0.0.1:{self.port}/nonexistent"
docs/HANDOFF.md:722:  - Ollama was validated as a normal-user foreground process bound solely to `127.0.0.1:11435`; direct `/api/tags` health returned four models.
docs/HANDOFF.md:723:  - Caddy 2.11.4 was validated as a normal-user foreground reverse proxy with its administration endpoint disabled and its sole listener at `192.168.0.189:11434`; the proxy forwarded to `127.0.0.1:11435`, and proxied `/api/tags` returned four models.
docs/HANDOFF.md:732:  - During the approved temporary test, the bearer verifier listened only on `127.0.0.1:11436`, Ollama listened only on `127.0.0.1:11435`, and direct Kali access to either backend port timed out.
docs/HANDOFF.md:819:- **Validated isolation:** During the approved temporary test, Ollama listened only on `127.0.0.1:11435` and the forward-auth verifier only on `127.0.0.1:11436`. Kali reached the Caddy gateway but direct Kali connections to ports `11435` and `11436` timed out.
test/llm_client/test_ollama_client.py:64:        with patch.dict(os.environ, {"OLLAMA_HOST": "http://127.0.0.1:99999"}):
src/llm_client/ollama_client.py:66:    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").strip()
test/llm_client/test_raw_chat.py:65:        with patch.dict(os.environ, {"OLLAMA_HOST": "http://127.0.0.1:1"}):
scripts/launch-soc-ui.sh:21:    "http://localhost:8200/ui"                               # 1. HashiCorp Vault
scripts/launch-soc-ui.sh:22:    "http://localhost:8929"                                  # 2. GitLab CE
scripts/launch-soc-ui.sh:23:    "http://localhost:8080"                                  # 3. Argo CD GitOps
scripts/launch-soc-ui.sh:24:    "http://localhost:9090"                                  # 4. Prometheus Server
scripts/launch-soc-ui.sh:25:    "http://localhost:9200"                                  # 5. Elasticsearch Engine
scripts/launch-soc-ui.sh:26:    "http://localhost:5601"                                  # 6. Kibana SIEM Dashboard
scripts/launch-soc-ui.sh:27:    "http://localhost:3000"                                  # 7. Grafana Metrics
scripts/launch-soc-ui.sh:28:    "http://localhost:8082"                                  # 8. Jenkins CI/CD
scripts/launch-soc-ui.sh:29:    "http://localhost:9000"                                  # 9. SonarQube SAST Gate
scripts/launch-soc-ui.sh:30:    "http://localhost:8085"                                  # 10. DefectDojo Compliance Hub
scripts/launch-soc-ui.sh:31:    "http://localhost:9005"                                  # 11. TheHive 4 SOAR
scripts/launch-soc-ui.sh:32:    "http://localhost:3100"                                  # 12. Langfuse Observability
scripts/launch-soc-ui.sh:37:    "HashiCorp Vault (:8200)"
scripts/launch-soc-ui.sh:38:    "GitLab CE (:8929)"
scripts/launch-soc-ui.sh:39:    "Argo CD GitOps (:8080)"
scripts/launch-soc-ui.sh:40:    "Prometheus (:9090)"
scripts/launch-soc-ui.sh:41:    "Elasticsearch SIEM (:9200)"
scripts/launch-soc-ui.sh:42:    "Kibana SIEM Visualizer (:5601)"
scripts/launch-soc-ui.sh:43:    "Grafana Dashboard (:3000)"
scripts/launch-soc-ui.sh:44:    "Jenkins CI/CD (:8082)"
scripts/launch-soc-ui.sh:45:    "SonarQube SAST (:9000)"
scripts/launch-soc-ui.sh:46:    "DefectDojo Hub (:8085)"
scripts/launch-soc-ui.sh:47:    "TheHive 4 SOAR (:9005)"
scripts/launch-soc-ui.sh:48:    "Langfuse Observability (:3100)"
scripts/sync-thehive-vault.py:9:THEHIVE_BASE = "http://127.0.0.1:9005"
scripts/sync-thehive-vault.py:10:VAULT_BASE = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/provision-jira-vault.py:12:VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
src/observability/shadow_fork_verifier.py:30:    rpc_url: str = "http://127.0.0.1:8545"
scripts/ingest-granular-siem.py:21:ELASTIC_URL = os.getenv("ELASTICSEARCH_URL", "http://192.168.0.150:9200")
src/observability/telemetry_client.py:47:    def __init__(self, base_url: str = "http://localhost:9090", timeout: float = 3.0):
src/observability/telemetry_client.py:105:        base_url: str = "http://localhost:9200",
src/observability/telemetry_client.py:184:        prometheus_url: str = "http://localhost:9090",
src/observability/telemetry_client.py:185:        elasticsearch_url: str = "http://localhost:9200",
src/incident/jira_dispatcher.py:13:    vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
docs/RUNBOOK.md:654:- Bind Ollama only to `127.0.0.1:11435`.
docs/RUNBOOK.md:662:Create a host-local Caddyfile outside the repository with automatic HTTPS and Caddy administration disabled, an explicit `bind 192.168.0.189`, and a `reverse_proxy 127.0.0.1:11435` site at `http://192.168.0.189:11434`. Validate it with:
docs/RUNBOOK.md:670:1. In a normal-user PowerShell session, set process-local `OLLAMA_HOST` to `127.0.0.1:11435` and process-local `OLLAMA_MODELS` to the existing approved host-local model store, then run `ollama.exe serve`.
docs/RUNBOOK.md:671:2. Confirm startup output reports `Listening on 127.0.0.1:11435`.
docs/RUNBOOK.md:683:Invoke-RestMethod http://127.0.0.1:11435/api/tags
docs/RUNBOOK.md:689:- Listener inspection showed Ollama solely at `127.0.0.1:11435` and Caddy solely at `192.168.0.189:11434`.
docs/RUNBOOK.md:722:  -> loopback-only forward-auth verifier at 127.0.0.1:11436
docs/RUNBOOK.md:723:  -> loopback-only Ollama backend at 127.0.0.1:11435
docs/RUNBOOK.md:779:- Preserve Ollama loopback binding at `127.0.0.1:11435`; do not expose Ollama directly to the LAN.
docs/RUNBOOK.md:803:- Caddy reverse-proxies only to `127.0.0.1:11435`.
scripts/run-dast.sh:4:# Override: DAST_TARGET=http://127.0.0.1:PORT   or   DAST_SERVE_DIR=some/dir
scripts/run-dast.sh:18:  TARGET="http://127.0.0.1:$PORT"
scripts/run-all-e2e.sh:201:addr = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
scripts/ship-siem-telemetry.py:69:    es_url = os.getenv("ELASTICSEARCH_URL", "http://127.0.0.1:9200/blockchain-soc-audit-logs/_doc")
scripts/ship-siem-telemetry.py:146:        _tool_status_line("HashiCorp Vault", "http://127.0.0.1:8200",
scripts/ship-siem-telemetry.py:149:        _tool_status_line("SonarQube SAST", "http://127.0.0.1:9000",
scripts/ship-siem-telemetry.py:152:        _tool_status_line("Jenkins Enterprise", "http://127.0.0.1:8082",
scripts/ship-siem-telemetry.py:160:        _tool_status_line("Anvil AVS Consensus", ":8545, :8546, :8547",
scripts/ship-siem-telemetry.py:164:        _tool_status_line("Elasticsearch SIEM", "http://127.0.0.1:9200",
scripts/ship-siem-telemetry.py:252:        print("[+] [PROMETHEUS LISTENER] Metrics endpoint listening on http://0.0.0.0:9101/metrics")
src/deployment/consensus_deployer.py:75:        rpc_url: str = "http://127.0.0.1:8545",
docs/pipeline-source-dump-2.md:460:        self.rpc = f"http://127.0.0.1:{port}"
docs/pipeline-source-dump-1.md:989:addr = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
docs/pipeline-source-dump-1.md:1106:        VAULT_ADDR = 'http://192.168.0.150:8200'
docs/pipeline-source-dump-1.md:1130:                      -Dsonar.host.url="http://127.0.0.1:9000" \
docs/pipeline-source-dump-1.md:1182:  VAULT_ADDR: "http://172.17.0.1:8200"
docs/pipeline-source-dump-1.md:1184:  JENKINS_ADDR: "http://172.17.0.1:8082"
scripts/ingest-defectdojo.py:32:DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://127.0.0.1:8085")
src/deployment/vault_secret_store.py:60:        self.vault_addr = (vault_addr or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")).rstrip("/")
scripts/run-sonar.sh:8:SONAR_ADDR="${SONAR_ADDR:-http://127.0.0.1:9000}"
scripts/run-sonar.sh:10:VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
src/consensus/avs_consensus.py:100:        self.rpc = f"http://127.0.0.1:{port}"
config/telemetry/prometheus.blockchain-soc.yml:8:# exporter:9100" target with no DNS record anywhere reachable from this
config/telemetry/prometheus.blockchain-soc.yml:18:      - targets: ["localhost:9090"]
config/telemetry/prometheus.blockchain-soc.yml:22:      # "cross-node-exporter:9100" removed: no DNS record resolves it from
config/telemetry/prometheus.blockchain-soc.yml:24:      # 8.8.8.8:53: no such host). localhost:9100 and 172.17.0.1:9100 are
config/telemetry/prometheus.blockchain-soc.yml:26:      - targets: ["localhost:9100", "172.17.0.1:9100"]
config/telemetry/prometheus.blockchain-soc.yml:32:      - targets: ["172.17.0.1:9101"]
scripts/export-env.sh.example:7:export OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"
scripts/provision-thehive-vault.py:9:THEHIVE = "http://127.0.0.1:9005"
scripts/provision-thehive-vault.py:10:VAULT = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/sync-defectdojo-metrics.py:33:VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/sync-defectdojo-metrics.py:35:URL = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8085") + "/api/v2"
scripts/sync-defectdojo-metrics.py:122:    thehive_url = os.environ.get("THEHIVE_URL", "http://127.0.0.1:9005")
scripts/sync-defectdojo-metrics.py:151:    thehive_url = os.environ.get("THEHIVE_URL", "http://127.0.0.1:9005")
scripts/exporter-daemon.py:29:    print("[+] [PROMETHEUS EXPORTER DAEMON] Serving metrics on http://0.0.0.0:9101/metrics...")
scripts/bootstrap-thehive-enterprise.py:8:BASE = "http://127.0.0.1:9005"
scripts/orchestrate-enterprise-integrations.sh:10:VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
scripts/orchestrate-enterprise-integrations.sh:11:JENKINS_ADDR="${JENKINS_ADDR:-http://127.0.0.1:8082}"
scripts/orchestrate-enterprise-integrations.sh:58:    "{\"data\":{\"token\":\"${DEFECTDOJO_TOKEN}\",\"url\":\"${DEFECTDOJO_URL:-http://127.0.0.1:8085}\"}}" token
scripts/vault-hive-pipeline.py:11:THEHIVE = "http://127.0.0.1:9005"
scripts/vault-hive-pipeline.py:12:VAULT = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/bootstrap-langfuse.py:107:LANGFUSE_HOST="http://127.0.0.1:3100"
docker/docker-compose.validators.yml:16:      - "8081:8081"
docker/docker-compose.validators.yml:20:      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8081/health', timeout=2)"]
docker/docker-compose.validators.yml:38:      - "8082:8082"
docker/docker-compose.validators.yml:42:      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8082/health', timeout=2)"]
docker/docker-compose.validators.yml:60:      - "8083:8083"
docker/docker-compose.validators.yml:64:      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8083/health', timeout=2)"]
scripts/notify-slack.py:8:VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
docs/CHECKLIST.md:362:  - Read-only discovery recorded a running `ollama.exe` process, current-user Startup-folder reference, a successful loopback `GET http://127.0.0.1:11434/api/tags` response, and no observed non-loopback established API connection at inspection time.
docs/CHECKLIST.md:381:- **Scope completed:** On the authorized Windows inference host, ran Ollama as a normal-user foreground process bound only to `127.0.0.1:11435`. Configured and ran Caddy as a normal-user foreground reverse proxy bound only to the approved private interface at port `11434`, forwarding to `127.0.0.1:11435`. Caddy administration was disabled for the validated process.
docs/CHECKLIST.md:386:  Invoke-RestMethod http://127.0.0.1:11435/api/tags
docs/CHECKLIST.md:391:- **Factual results:** Ollama listener inspection showed exactly `127.0.0.1:11435`; direct backend health returned four models. Caddy validation returned `Valid configuration`; Caddy listener inspection showed exactly `192.168.0.189:11434`; Caddy administration was disabled. Local proxy health succeeded and proxied `/api/tags` returned four models.
docs/CHECKLIST.md:434:- **Factual results:** Caddy static validation succeeded with strict SNI/Host enforcement enabled for client authentication. During the approved temporary test, Ollama listened only on `127.0.0.1:11435` and the verifier only on `127.0.0.1:11436`; direct Kali connections to those backend ports timed out. A valid mTLS request without a Bearer credential returned HTTP `401`. The verifier recorded an allow decision when the configured Bearer credential was supplied.
docs/CHECKLIST.md:1084:| P08-001 | Deploy Prometheus plus ELK, or document Grafana/Loki lightweight replacement. | ✅ | Complete and verified 2026-10-10: Configured dual observability architecture in `docs/OBSERVABILITY_STACK.md` and scrape targets in `config/telemetry/prometheus.blockchain-soc.yml`; implemented `src/observability/telemetry_stack.py` supporting both full enterprise ELK profile (`:9090`, `:9200`, `:5601`) and lightweight Grafana/Loki replacement profile (`:9090`, `:3100`, `:3000`); verified live running Docker host services (Prometheus 200, Elasticsearch 401, Kibana 200, Grafana 200); 10 observability unit tests passed, 29 deployment tests passed, 39 consensus tests passed, 42 agent tests passed, 14 LLM client tests passed, 18 storage tests passed, 20 MCP tests passed, strict manifest ingestion valid, and 83 Hardhat regression tests passed. |
docs/CHECKLIST.md:1085:| P08-002 | Implement real Prometheus and ELK telemetry query functions. | ✅ | Complete and verified 2026-10-10: Implemented `src/observability/telemetry_client.py` containing `PrometheusQueryClient` (instant queries `/api/v1/query`, range queries `/api/v1/query_range`, scalar gauge extraction), `ElasticsearchQueryClient` (DSL search queries `/_search`, document indexing `/_doc`, security event filtering by finding ID and category, basic auth header injection), and `SOCTelemetryClient` (unified metrics snapshot compilation and security event correlation); verified live queries against host Prometheus (:9090); 19 observability unit tests passed, 29 deployment tests passed, 39 consensus tests passed, 42 agent tests passed, 14 LLM client tests passed, 18 storage tests passed, 20 MCP tests passed, strict manifest ingestion valid, and 83 Hardhat regression tests passed. |
deploy/thehive/docker-compose.yml:7:      - "9005:9000"
```

### 2b. Supplementary broader sweep (any `:NN` to `:NNNNN` after a word
boundary, plus the same three IP/host prefixes) -- added because the exact
patterns above are 4-digit-prefix-only and miss real ports used by this
project: Ollama's 5-digit `11434`/`11435`/`11436`, Redis's `6379`,
GitLab SSH's `2222`, ArgoCD's `31703`, Kibana's `5601`, K3s's `6443`/`6444`/
`10xxx` range, etc. Included in full per "so nothing is missed" -- this list
is noisier (also catches non-port colon patterns like timestamps, `uid:gid`,
and Ollama model names like `qwen2.5:32b`); Part 3 below separates the real
services from that noise.

```
.gitlab-ci.yml:8:  VAULT_ADDR: "http://172.17.0.1:8200"
.gitlab-ci.yml:10:  JENKINS_ADDR: "http://172.17.0.1:8082"
.gitlab-ci.yml:15:  ARGOCD_ADDR: "https://172.17.0.1:31703"
.gitlab-ci.yml:34:  image: node:24.19.0-bookworm-slim
.gitlab-ci.yml:58:  image: node:24.19.0-bookworm-slim
.gitlab-ci.yml:73:  image: node:24.19.0-bookworm-slim
Jenkinsfile:5:        VAULT_ADDR = 'http://192.168.0.150:8200'
Jenkinsfile:29:                      -Dsonar.host.url="http://127.0.0.1:9000" \
docker-compose.deploy.yml:10:      - "8545:8545"
docker-compose.deploy.yml:27:      - RPC_URL=http://testnet-rpc:8545
docker-compose.test.yml:15:    user: "1000:1000"
docker-compose.test.yml:35:    user: "1000:1000"
docker-compose.test.yml:39:      - "8545:8545"
docker-compose.test.yml:51:    user: "1000:1000"
docker-compose.test.yml:71:    user: "1000:1000"
docker-compose.test.yml:80:      - "9090:9090"
docker-compose.yml:8:    ports: ["6379:6379"]
test/report-render.test.mjs:13:      timestamp: "2026-10-13T06:00:00Z",
test/agents/test_agent_g_guardrail.py:32:        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=G model=qwen2.5:32b ctx=8192: Host unavailable"
test/agents/test_agent_b_threat_hunter.py:27:        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=B model=deepseek-r1:32b ctx=16384: Host unavailable"
test/report-fixture-redaction.test.mjs:14:      timestamp: "2026-10-13T07:00:00Z",
test/agents/test_agent_e_incident_commander.py:32:        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=E model=qwen2.5:32b ctx=8192: Host unavailable"
test/agents/test_agent_c_compliance_judge.py:35:        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=C model=qwen2.5:32b ctx=8192: Host unavailable"
test/llm_client/test_raw_chat.py:24:            "model": "qwen2.5-coder:32b",
test/llm_client/test_raw_chat.py:65:        with patch.dict(os.environ, {"OLLAMA_HOST": "http://127.0.0.1:1"}):
test/llm_client/test_raw_chat.py:69:            self.assertIn("deepseek-r1:32b", reply)
test/llm_client/test_model_lifecycle.py:18:                {"name": "qwen2.5-coder:32b", "size_vram": 19000000000}
test/llm_client/test_model_lifecycle.py:26:            self.assertEqual(models[0]["name"], "qwen2.5-coder:32b")
test/llm_client/test_model_lifecycle.py:30:        running_models = [{"name": "deepseek-r1:32b"}]
test/llm_client/test_model_lifecycle.py:48:            self.assertEqual(initial[0]["name"], "deepseek-r1:32b")
test/llm_client/test_model_lifecycle.py:51:            purge_res = purge_model("deepseek-r1:32b")
test/llm_client/test_model_lifecycle.py:63:                self.assertEqual(ctx["model"], "qwen2.5-coder:32b")
test/llm_client/test_model_lifecycle.py:65:        self.assertIn("qwen2.5-coder:32b", purged_models)
test/consensus/test_drill_scenarios.py:126:                block_hash=f"0xhonest{i:04x}",
test/consensus/test_drill_scenarios.py:127:                parent_hash=f"0xhonest{i-1:04x}" if i > 0 else "0xgenesis",
test/consensus/test_drill_scenarios.py:137:                block_hash=f"0xrogue{i:04x}",
test/compliance/test_drill_screening_pipeline.py:141:            created_at_override="2026-10-12T12:00:00Z",
test/observability/test_telemetry_stack.py:23:        self.assertEqual(ep.url, "http://127.0.0.1:9090/metrics")
test/observability/test_telemetry_stack.py:83:            url="http://localhost:9200/",
test/observability/test_lifecycle_telemetry.py:39:            deployed_at="2026-10-10T12:00:00Z",
test/observability/test_lifecycle_telemetry.py:68:            timestamp="2026-10-10T12:00:00Z",
test/observability/test_lifecycle_telemetry.py:95:            timestamp="2026-10-10T12:00:00Z",
test/observability/test_lifecycle_telemetry.py:154:            deployed_at="2026-10-10T12:00:00Z",
docs/HANDOFF.md:582:  - Results: Implemented `docker-compose.test.yml` defining four isolated test services (`mcp-anvil`, `mcp-storage`, `mcp-forensics`, `mcp-telemetry`) on bridge network `mcp-test-network`; configured unprivileged container UID (`1000:1000`), resource limits, and read-only evidence mounts.
docs/HANDOFF.md:607:  - Results: Enriches normalized findings with MITRE ATT&CK technique IDs, CIS Controls v8 identifiers, ISO/IEC 27001:2022 controls, and CSET assessment domains; provides deterministic priority mapping for host governance versus smart contract vulnerabilities with baseline fallbacks; supports CLI execution.
docs/HANDOFF.md:712:  - Mythril `v0.24.8` was validated from `mythril/myth:latest` digest `sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff` in a hardened no-network, read-only container with tmpfs-only writable paths, dropped capabilities, and no-new-privileges. No source, bytecode, RPC target, contract scan, symbolic analysis, or formal proof was run.
docs/HANDOFF.md:717:  - With explicit approval, redundant `deepseek-r1:32b` was removed; post-removal validation retained `deepseek-r1:32b-stable`.
docs/HANDOFF.md:718:  - Final approved local set: `qwen2.5-coder:32b`, `deepseek-r1:32b-stable`, `qwen3.5:9b`, and `qwen3:32b`.
docs/HANDOFF.md:722:  - Ollama was validated as a normal-user foreground process bound solely to `127.0.0.1:11435`; direct `/api/tags` health returned four models.
docs/HANDOFF.md:723:  - Caddy 2.11.4 was validated as a normal-user foreground reverse proxy with its administration endpoint disabled and its sole listener at `192.168.0.189:11434`; the proxy forwarded to `127.0.0.1:11435`, and proxied `/api/tags` returned four models.
docs/HANDOFF.md:732:  - During the approved temporary test, the bearer verifier listened only on `127.0.0.1:11436`, Ollama listened only on `127.0.0.1:11435`, and direct Kali access to either backend port timed out.
docs/HANDOFF.md:818:- **Validated enforcement:** Caddy configuration validation passed with strict SNI/Host enforcement enabled for mandatory TLS client authentication. The server certificate was reissued under the existing private CA with `DNS:ollama-mtls.home.arpa` and `IP:192.168.0.189` SANs, and its key match and CA chain were verified.
docs/HANDOFF.md:819:- **Validated isolation:** During the approved temporary test, Ollama listened only on `127.0.0.1:11435` and the forward-auth verifier only on `127.0.0.1:11436`. Kali reached the Caddy gateway but direct Kali connections to ports `11435` and `11436` timed out.
docs/WALKTHROUGH_SCRIPT.md:5:**Target Duration:** 3:30 – 4:30 minutes  
docs/WALKTHROUGH_SCRIPT.md:11:### Scene 1: Introduction & The Core Problem (0:00 – 0:45)
docs/WALKTHROUGH_SCRIPT.md:22:### Scene 2: Architectural Defense-in-Depth & OPA Boundaries (0:45 – 1:45)
docs/WALKTHROUGH_SCRIPT.md:31:### Scene 3: Dual-Path Verification & Recruiter Demo (1:45 – 3:00)
docs/WALKTHROUGH_SCRIPT.md:42:### Scene 4: Empirical Benchmarks & Standalone Dashboard (3:00 – 4:00)
docs/WALKTHROUGH_SCRIPT.md:55:### Scene 5: Conclusion & Repository Access (4:00 – 4:30)
docs/HITL_GATEWAY.md:22:         expires_at="2026-10-14T00:00:00Z",
docs/pipeline-source-dump-2.md:66:                    "flagged": None, "detail": str(exc)[:120]}
docs/pipeline-source-dump-2.md:93:    print(f"[+] OFAC screen {demo[:12]}...: status={res['status']} "
docs/pipeline-source-dump-2.md:138:OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", os.getenv("OLLAMA_HOST", "http://192.168.0.189:11434"))
docs/pipeline-source-dump-2.md:199:                "reason": f"ollama unreachable: {str(exc)[:100]}", "raw": "",
docs/pipeline-source-dump-2.md:206:                "reason": f"unparseable ollama response: {str(exc)[:100]}", "raw": "",
docs/pipeline-source-dump-2.md:233:                "reason": raw.strip().replace("\n", " ")[:200], "raw": raw.strip()[:200]}
docs/pipeline-source-dump-2.md:237:            "raw": raw.strip()[:200]}
docs/pipeline-source-dump-2.md:274:                 f"{(f.get('description') or '').strip()[:160]}" for f in findings]
docs/pipeline-source-dump-2.md:308:              f"model={d['model']} :: {d['reason'][:70]}")
docs/pipeline-source-dump-2.md:460:        self.rpc = f"http://127.0.0.1:{port}"
docs/pipeline-source-dump-2.md:495:            raise ToolingError(f"deploy {name} failed: {(err or out).strip()[:200]}")
docs/pipeline-source-dump-2.md:506:            raise ToolingError(f"victim deposit failed: {err.strip()[:200]}")
docs/pipeline-source-dump-2.md:595:        raise ToolingError(f"forge build failed: {(err or out).strip()[:300]}")
docs/pipeline-source-dump-2.md:634:            print(f"    [*] node {obs['node_id']} ({obs['validator']}) vault={obs['vault_address'][:10]}... "
docs/pipeline-source-dump-2.md:639:                            target=target_src, detail=str(exc)[:250],
docs/pipeline-source-dump-2.md:1323:        print(f"    [-] evidence DB seal warning: {str(exc)[:100]}")
docs/pipeline-source-dump-2.md:1325:          f"root SHA-256: {seal['root_sha256'][:24]}...")
docs/pipeline-source-dump-2.md:1371:        print(f"    [-] TheHive stderr: {proc.stderr.strip()[:200]}")
docs/pipeline-source-dump-2.md:2313:               <div class="infra-name" style="font-size:12px;">L${a.level} · ${escapeHtml(a.name)}</div>
docs/pipeline-source-dump-2.md:2319:        <div class="section-card" style="margin-bottom:10px;">
docs/pipeline-source-dump-2.md:2321:            <div class="section-title" style="margin-bottom:0; font-size:14px;">${escapeHtml(sub)}</div>
docs/pipeline-source-dump-2.md:2353:        <p style="font-size:13px; color:#cbd5e1; margin-top:14px;">Assessed this run — real pass/fail evidence, with the subdimension's claimed level capped below any failed activity:</p>
docs/pipeline-source-dump-2.md:2356:        <p style="font-size:13px; color:#cbd5e1; margin-top:18px;">Not assessed — no tooling in this pipeline can check these; they require manual or organizational evidence (e.g. security champions programs, training records, threat-modeling process, access reviews):</p>
docs/pipeline-source-dump-2.md:2482:      <td class="finding-cell"><b>${escapeHtml(f.title)}</b><div class="dim" style="font-size:12px; margin-top:2px;">${escapeHtml(f.description)}</div></td>
docs/pipeline-source-dump-2.md:2707:    .badge { display:inline-block; padding:2px 9px; border-radius:5px; font-size:10.5px; font-weight:700; letter-spacing:0.2px; white-space: nowrap; }
docs/pipeline-source-dump-2.md:2824:          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Severity Breakdown</div><div class="chart-box"><canvas id="chartSeverity"></canvas></div></div>
docs/pipeline-source-dump-2.md:2825:          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Findings by Zone</div><div class="chart-box"><canvas id="chartZone"></canvas></div></div>
docs/pipeline-source-dump-2.md:2826:          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Gate Status by Policy</div><div class="chart-box"><canvas id="chartGates"></canvas></div></div>
docs/pipeline-source-dump-2.md:2827:          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Run History Trend</div><div class="chart-box"><canvas id="chartTrend"></canvas></div></div>
docs/pipeline-source-dump-2.md:2892:          <div class="infra-detail" style="text-align:left; max-width:100%; margin-bottom:6px;">${escapeHtml(v104.hashicorp_vault?.detail || "")}</div>
docs/pipeline-source-dump-2.md:2897:          <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(v104.k3s_kubernetes?.node || "")} ${escapeHtml(v104.k3s_kubernetes?.version || "")} ${escapeHtml(v104.k3s_kubernetes?.detail || "")}</div>
docs/pipeline-source-dump-2.md:2901:          <p style="font-size:13px; color:#cbd5e1;">Categories actually triggered this run:</p>
docs/pipeline-source-dump-2.md:2908:          <div class="infra-row" style="margin-top:14px;">
docs/pipeline-source-dump-2.md:2912:          <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(v104.openscap?.standard || "")}</div>
docs/pipeline-source-dump-2.md:2944:        <details class="collapsible" style="margin-top:16px;">
docs/OBSERVABILITY_STACK.md:10:| **Prometheus** | `9090` | host | `cross-prometheus` (v2.51.0) | Metric collection from agents, AVS, RASP (`:9100-9102`) |
docs/OBSERVABILITY_STACK.md:19:- **Metrics Endpoint**: `http://localhost:9090/metrics`
docs/OBSERVABILITY_STACK.md:25:- **Metrics Endpoint**: `http://localhost:9090`
docs/OBSERVABILITY_STACK.md:26:- **Dashboard Service**: `http://localhost:3000`
docs/architecture/VALIDATOR_SIMULATION.md:30:curl -s http://localhost:8081/health | jq .
docs/architecture/VALIDATOR_SIMULATION.md:31:curl -s http://localhost:8082/health | jq .
docs/architecture/VALIDATOR_SIMULATION.md:32:curl -s http://localhost:8083/health | jq .
test/agents/test_agent_d_red_teamer.py:34:        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=D model=deepseek-r1:32b ctx=16384: Host unavailable"
test/agents/test_agent_f_logic_analyzer.py:34:        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=F model=deepseek-r1:32b ctx=16384: Host unavailable"
test/consensus/test_reorg_monitor.py:36:                block_hash=f"0x{n:064x}",
test/consensus/test_reorg_monitor.py:89:                block_hash=f"0x{n:062x}aa",
test/consensus/test_reorg_monitor.py:106:                block_hash=f"0x{n:062x}ff",
test/consensus/test_reorg_monitor.py:128:                block_hash=f"0x{n:062x}11",
test/consensus/test_reorg_monitor.py:141:                block_hash=f"0x{n:062x}99",
test/hardhat/placeholder.test.cjs:217:        : { id: "TEST-1", aliases: [], withdrawn: "2026-01-01T00:00:00Z" },
test/hardhat/placeholder.test.cjs:219:    assert.equal(output.advisories[0].withdrawn, "2026-01-01T00:00:00Z");
test/hardhat/placeholder.test.cjs:1070:      "report_datetime_start=2026-10-07 20:49:23",
test/hardhat/placeholder.test.cjs:1071:      "report_datetime_end=2026-10-07 20:50:33",
test/hardhat/placeholder.test.cjs:1210:      ["report_datetime_end=2026-10-07 20:50:33\n", ""],
test/hardhat/placeholder.test.cjs:1211:      ["2026-10-07 20:50:33", "2026-02-30 20:50:33"],
test/hardhat/placeholder.test.cjs:1212:      ["2026-10-07 20:50:33", "2026-10-07 20:48:00"],
test/mcp_middleware/test_host_forensics.py:37:002:  000:000   0000002048   0000206847   0000204800   Linux (0x83)
test/mcp_middleware/test_host_forensics.py:38:003:  000:001   0000206848   0000411647   0000204800   Linux Swap (0x82)
e version:3:     Active: [0;1;32mactive (running)[0m since Sun 2026-09-27 11:30:56 EDT; 1min 41s ago
e version:12:             └─[0;38:5:245m46039 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock[0m
e version:14:Sep 27 11:30:55 Saleem dockerd[46039]: time="2026-09-27T11:30:55.328907045-04:00" level=info msg="Restoring containers: start."
e version:15:Sep 27 11:30:55 Saleem dockerd[46039]: time="2026-09-27T11:30:55.376601741-04:00" level=info msg="Deleting nftables IPv4 rules" error="running nft: /dev/stdin:1:17-30: Error: Could not process rule: No such file or directory\ndelete table ip docker-bridges\n                ^^^^^^^^^^^^^^\n exit status 1"
e version:16:Sep 27 11:30:55 Saleem dockerd[46039]: time="2026-09-27T11:30:55.404562858-04:00" level=info msg="Deleting nftables IPv6 rules" error="running nft: /dev/stdin:1:18-31: Error: Could not process rule: No such file or directory\ndelete table ip6 docker-bridges\n                 ^^^^^^^^^^^^^^\n exit status 1"
e version:17:Sep 27 11:30:56 Saleem dockerd[46039]: time="2026-09-27T11:30:56.355801281-04:00" level=info msg="Loading containers: done."
e version:18:Sep 27 11:30:56 Saleem dockerd[46039]: time="2026-09-27T11:30:56.365237221-04:00" level=info msg="Docker daemon" commit=464cd50 containerd-snapshotter=true storage-driver=overlayfs version=29.8.1
e version:19:Sep 27 11:30:56 Saleem dockerd[46039]: time="2026-09-27T11:30:56.365326547-04:00" level=info msg="Initializing buildkit"
e version:20:Sep 27 11:30:56 Saleem dockerd[46039]: time="2026-09-27T11:30:56.444308801-04:00" level=info msg="Completed buildkit initialization"
e version:21:Sep 27 11:30:56 Saleem dockerd[46039]: time="2026-09-27T11:30:56.449303118-04:00" level=info msg="Daemon has completed initialization"
e version:22:Sep 27 11:30:56 Saleem dockerd[46039]: time="2026-09-27T11:30:56.449655243-04:00" level=info msg="API listen on /run/docker.sock"
e version:23:Sep 27 11:30:56 Saleem systemd[1]: Started docker.service - Docker Application Container Engine.
src/incident/safe_pause_builder.py:39:    print(f"[+] Safe Emergency Proposal built: to={tx['to']} calldata={tx['data']} hash={tx['safeTxHash'][:18]}...")
src/agents/agent_g_guardrail.py:48:        "sanitization_notes": response_text[:250].strip(),
test/consensus/test_selfish_mining_detector.py:31:                block_hash=f"0x{i:064x}",
test/consensus/test_selfish_mining_detector.py:32:                parent_hash=f"0x{i-1:064x}",
test/consensus/test_selfish_mining_detector.py:47:                block_hash=f"0x{i:064x}",
test/consensus/test_selfish_mining_detector.py:48:                parent_hash=f"0x{i-1:064x}",
test/consensus/test_selfish_mining_detector.py:65:                block_hash=f"0x{i:064x}",
test/consensus/test_selfish_mining_detector.py:66:                parent_hash=f"0x{i-1:064x}",
test/consensus/test_selfish_mining_detector.py:84:                block_hash=f"0x{i:064x}",
test/consensus/test_selfish_mining_detector.py:85:                parent_hash=f"0x{i-1:064x}",
test/consensus/test_selfish_mining_detector.py:102:                block_hash=f"0x{i:064x}",
test/consensus/test_selfish_mining_detector.py:103:                parent_hash=f"0x{i-1:064x}",
test/compliance/test_sar_generator.py:61:            created_at_override="2026-10-12T12:00:00Z",
test/compliance/test_sar_generator.py:78:            created_at_override="2026-10-12T12:00:00Z",
test/compliance/test_sar_generator.py:88:            created_at_override="2026-10-12T12:00:00Z",
test/compliance/test_sar_generator.py:115:            created_at_override="2026-10-12T12:00:00Z",
test/compliance/test_sar_generator.py:122:            created_at_override="2026-10-12T12:00:00Z",
src/incident/jira_dispatcher.py:13:    vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
src/agents/swarm_orchestrator.py:39:OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", os.getenv("OLLAMA_HOST", "http://192.168.0.189:11434"))
src/agents/swarm_orchestrator.py:100:                "reason": f"ollama unreachable: {str(exc)[:100]}", "raw": "",
src/agents/swarm_orchestrator.py:107:                "reason": f"unparseable ollama response: {str(exc)[:100]}", "raw": "",
src/agents/swarm_orchestrator.py:134:                "reason": raw.strip().replace("\n", " ")[:200], "raw": raw.strip()[:200]}
src/agents/swarm_orchestrator.py:138:            "raw": raw.strip()[:200]}
src/agents/swarm_orchestrator.py:175:                 f"{(f.get('description') or '').strip()[:160]}" for f in findings]
src/agents/swarm_orchestrator.py:209:              f"model={d['model']} :: {d['reason'][:70]}")
src/wallet/hsm_signer_interface.py:104:        r = int.from_bytes(packed_sig[:32], byteorder="big")
src/wallet/hsm_signer_interface.py:105:        s = int.from_bytes(packed_sig[32:64], byteorder="big")
src/deployment/vault_secret_store.py:60:        self.vault_addr = (vault_addr or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")).rstrip("/")
src/deployment/vault_secret_store.py:84:        lease_id = f"lease-{hashlib.sha256(f'{secret_path}:{ts}'.encode('utf-8')).hexdigest()[:12]}"
src/agents/agent_f_logic_analyzer.py:52:        "mathematical_rationale": response_text[:250].strip(),
src/wallet/hsm_emulator.py:182:        pub_hex = f"04{pub_x:064x}{pub_y:064x}"
src/wallet/hsm_emulator.py:185:        pub_bytes = bytes.fromhex(f"{pub_x:064x}{pub_y:064x}")
src/wallet/hsm_emulator.py:241:        sig_hex = f"{r:064x}{s:064x}{v:02x}"
src/wallet/hsm_emulator.py:252:        pub_x = int(pub_clean[:64], 16)
src/observability/rasp_shield.py:214:        finding_id = f"RASP-{hashlib.sha256(finding_seed).hexdigest()[:12].upper()}"
scripts/launch-soc-ui.sh:21:    "http://localhost:8200/ui"                               # 1. HashiCorp Vault
scripts/launch-soc-ui.sh:22:    "http://localhost:8929"                                  # 2. GitLab CE
scripts/launch-soc-ui.sh:23:    "http://localhost:8080"                                  # 3. Argo CD GitOps
scripts/launch-soc-ui.sh:24:    "http://localhost:9090"                                  # 4. Prometheus Server
scripts/launch-soc-ui.sh:25:    "http://localhost:9200"                                  # 5. Elasticsearch Engine
scripts/launch-soc-ui.sh:26:    "http://localhost:5601"                                  # 6. Kibana SIEM Dashboard
scripts/launch-soc-ui.sh:27:    "http://localhost:3000"                                  # 7. Grafana Metrics
scripts/launch-soc-ui.sh:28:    "http://localhost:8082"                                  # 8. Jenkins CI/CD
scripts/launch-soc-ui.sh:29:    "http://localhost:9000"                                  # 9. SonarQube SAST Gate
scripts/launch-soc-ui.sh:30:    "http://localhost:8085"                                  # 10. DefectDojo Compliance Hub
scripts/launch-soc-ui.sh:31:    "http://localhost:9005"                                  # 11. TheHive 4 SOAR
scripts/launch-soc-ui.sh:32:    "http://localhost:3100"                                  # 12. Langfuse Observability
scripts/launch-soc-ui.sh:37:    "HashiCorp Vault (:8200)"
scripts/launch-soc-ui.sh:38:    "GitLab CE (:8929)"
scripts/launch-soc-ui.sh:39:    "Argo CD GitOps (:8080)"
scripts/launch-soc-ui.sh:40:    "Prometheus (:9090)"
scripts/launch-soc-ui.sh:41:    "Elasticsearch SIEM (:9200)"
scripts/launch-soc-ui.sh:42:    "Kibana SIEM Visualizer (:5601)"
scripts/launch-soc-ui.sh:43:    "Grafana Dashboard (:3000)"
scripts/launch-soc-ui.sh:44:    "Jenkins CI/CD (:8082)"
scripts/launch-soc-ui.sh:45:    "SonarQube SAST (:9000)"
scripts/launch-soc-ui.sh:46:    "DefectDojo Hub (:8085)"
scripts/launch-soc-ui.sh:47:    "TheHive 4 SOAR (:9005)"
scripts/launch-soc-ui.sh:48:    "Langfuse Observability (:3100)"
scripts/sync-thehive-vault.py:9:THEHIVE_BASE = "http://127.0.0.1:9005"
scripts/sync-thehive-vault.py:10:VAULT_BASE = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/sync-thehive-vault.py:82:            print(f"    -> Indexed observable: [{obs['dataType']}] {obs['data'][:32]}...")
scripts/provision-jira-vault.py:12:VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/audit-completion-gate.py:41:        for t in unresolved_tasks[:10]:
config/telemetry/prometheus.blockchain-soc.yml:8:# exporter:9100" target with no DNS record anywhere reachable from this
config/telemetry/prometheus.blockchain-soc.yml:18:      - targets: ["localhost:9090"]
config/telemetry/prometheus.blockchain-soc.yml:22:      # "cross-node-exporter:9100" removed: no DNS record resolves it from
config/telemetry/prometheus.blockchain-soc.yml:24:      # 8.8.8.8:53: no such host). localhost:9100 and 172.17.0.1:9100 are
config/telemetry/prometheus.blockchain-soc.yml:26:      - targets: ["localhost:9100", "172.17.0.1:9100"]
config/telemetry/prometheus.blockchain-soc.yml:32:      - targets: ["172.17.0.1:9101"]
docs/architecture/MODEL_SCHEDULE.md:17:| **Agent A** | Smart Contract Auditor | `qwen2.5-coder:32b` (Q4_K_M) | 32,768 (32K) | `qwen2.5-coder:14b` (Q4_K_M) | 16,384 (16K) | 180s |
docs/architecture/MODEL_SCHEDULE.md:18:| **Agent B** | SIEM Threat Hunter | `deepseek-r1:32b` (Q4_K_M) | 16,384 (16K) | `deepseek-r1:14b` (Q4_K_M) | 8,192 (8K) | 180s |
docs/architecture/MODEL_SCHEDULE.md:19:| **Agent C** | Compliance Judge | `qwen2.5:32b` (Q4_K_M) | 8,192 (8K) | `qwen2.5:14b` (Q4_K_M) | 8,192 (8K) | 180s |
docs/architecture/MODEL_SCHEDULE.md:20:| **Agent D** | Red Teamer / Exploit Gen | `deepseek-r1:32b` (Q4_K_M) | 16,384 (16K) | `deepseek-r1:14b` (Q4_K_M) | 8,192 (8K) | 180s |
docs/architecture/MODEL_SCHEDULE.md:21:| **Agent E** | Incident Commander | `qwen2.5:32b` (Q4_K_M) | 8,192 (8K) | `qwen2.5:14b` (Q4_K_M) | 8,192 (8K) | 180s |
docs/architecture/MODEL_SCHEDULE.md:22:| **Agent F** | Deep Logic Analyzer | `deepseek-r1:32b` (Q4_K_M) | 32,768 (32K) | `deepseek-r1:14b` (Q4_K_M) | 16,384 (16K) | 180s |
docs/architecture/MODEL_SCHEDULE.md:23:| **Agent G** | Guardrail Watchdog | `qwen2.5-coder:32b` (Q4_K_M) | 32,768 (32K) | `qwen2.5-coder:7b` (Q4_K_M) | 16,384 (16K) | 300s (Capped) |
test/agents/test_agent_a_auditor.py:27:        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=A model=qwen2.5-coder:32b ctx=32768: Host unavailable"
src/agents/agent_a_auditor.py:69:        "details": response_text[:200] if response_text else "No details extracted.",
src/agents/agent_a_auditor.py:123:                "finding_id": f"FINDING-A-WLT-{idx+1:03d}",
src/consensus/graph_enricher.py:99:        finding_id = f"c6-reorg-{digest[:12]}"
src/consensus/graph_enricher.py:143:                f"#{event.common_ancestor_number} ({event.common_ancestor_hash[:10]}...)."
src/consensus/graph_enricher.py:167:        finding_id = f"c6-concentration-{digest[:12]}"
src/consensus/graph_enricher.py:230:        finding_id = f"c6-selfish-{digest[:12]}"
src/consensus/graph_enricher.py:293:        finding_id = f"c6-eclipse-{digest[:12]}"
scripts/mirror-ofac.py:99:    print(f"    sdn.csv sha256: {snapshot['sdn_csv_sha256'][:16]}...  downloaded_at: {snapshot['downloaded_at']}")
src/forensics/sanitizer.py:32:    digest = hashlib.sha256(text_bytes).hexdigest()[:16]
test/llm_client/test_ollama_client.py:41:        with patch.dict(os.environ, {"OLLAMA_HOST": "192.168.1.50:11434"}):
test/llm_client/test_ollama_client.py:42:            self.assertEqual(get_ollama_base_url(), "http://192.168.1.50:11434")
test/llm_client/test_ollama_client.py:44:        with patch.dict(os.environ, {"OLLAMA_HOST": "https://gpu-node:11434/"}):
test/llm_client/test_ollama_client.py:45:            self.assertEqual(get_ollama_base_url(), "https://gpu-node:11434")
test/llm_client/test_ollama_client.py:48:        res = purge_model("qwen2.5-coder:32b")
test/llm_client/test_ollama_client.py:50:        self.assertEqual(res["model"], "qwen2.5-coder:32b")
test/llm_client/test_ollama_client.py:57:                self.assertEqual(ctx["model"], "deepseek-r1:32b-stable")
test/llm_client/test_ollama_client.py:61:        self.assertEqual(purged, ["deepseek-r1:32b-stable"])
test/llm_client/test_ollama_client.py:64:        with patch.dict(os.environ, {"OLLAMA_HOST": "http://127.0.0.1:99999"}):
test/llm_client/test_ollama_client.py:74:            self.assertEqual(routing1["A"], "qwen2.5-coder:32b")
test/llm_client/test_ollama_client.py:75:            self.assertEqual(routing1["G"], "qwen2.5-coder:32b")
test/llm_client/test_ollama_client.py:79:            self.assertEqual(routing2["A"], "qwen2.5-coder:14b")
docs/CHECKLIST.md:125:| P00-005 | Install Ollama on Windows and record the approved local model set. | ✅ | Verified 2026-09-30: Ollama 0.34.4 and final four-model local set validated; redundant `deepseek-r1:32b` removed; documentation commit `afb049f37ad850f67c3dbc534a892b69634f5a1c`; GitLab Pipeline #18 passed; `main`, `gitlab/main`, and `origin/main` resolved to the same SHA. |
docs/CHECKLIST.md:326:  - `docker pull mythril/myth:latest` completed. Local image inspection reported digest `sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff`.
docs/CHECKLIST.md:343:- **Scope completed:** Read-only inspection of the authorized Windows AI-inference host; factual Ollama installed-state, process/startup state, local listener/API availability, local model inventory, and per-model metadata capture; explicit removal of the redundant `deepseek-r1:32b` tag after approval; post-removal validation of the retained stable DeepSeek tag and final model inventory; documentation update; local commit; GitLab-first post; GitLab CI verification; GitHub post; and three-way SHA synchronization.
docs/CHECKLIST.md:350:  ollama show deepseek-r1:32b
docs/CHECKLIST.md:351:  ollama show qwen2.5-coder:32b
docs/CHECKLIST.md:352:  ollama show deepseek-r1:32b-stable
docs/CHECKLIST.md:354:  ollama show qwen3:32b
docs/CHECKLIST.md:355:  ollama rm deepseek-r1:32b
docs/CHECKLIST.md:357:  ollama show deepseek-r1:32b-stable
docs/CHECKLIST.md:358:  ollama show deepseek-r1:32b
docs/CHECKLIST.md:362:  - Read-only discovery recorded a running `ollama.exe` process, current-user Startup-folder reference, a successful loopback `GET http://127.0.0.1:11434/api/tags` response, and no observed non-loopback established API connection at inspection time.
docs/CHECKLIST.md:363:  - Initial local inventory contained five tags: `deepseek-r1:32b`, `qwen2.5-coder:32b`, `deepseek-r1:32b-stable`, `qwen3.5:9b`, and `qwen3:32b`.
docs/CHECKLIST.md:364:  - Per-model metadata was captured before removal. `deepseek-r1:32b` and `deepseek-r1:32b-stable` each reported Qwen2 architecture, 32.8B parameters, 131072 context length, 5120 embedding length, and `Q4_K_M` quantization; the stable tag included a `num_ctx 4096` override.
docs/CHECKLIST.md:365:  - After explicit approval, `ollama rm deepseek-r1:32b` returned `deleted 'deepseek-r1:32b'`.
docs/CHECKLIST.md:366:  - Final retained approved local model set: `qwen2.5-coder:32b` (19 GB), `deepseek-r1:32b-stable` (19 GB), `qwen3.5:9b` (6.6 GB), and `qwen3:32b` (20 GB).
docs/CHECKLIST.md:367:  - Post-removal `ollama show deepseek-r1:32b-stable` succeeded; `ollama show deepseek-r1:32b` returned `Error: model 'deepseek-r1:32b' not found`.
docs/CHECKLIST.md:381:- **Scope completed:** On the authorized Windows inference host, ran Ollama as a normal-user foreground process bound only to `127.0.0.1:11435`. Configured and ran Caddy as a normal-user foreground reverse proxy bound only to the approved private interface at port `11434`, forwarding to `127.0.0.1:11435`. Caddy administration was disabled for the validated process.
docs/CHECKLIST.md:386:  Invoke-RestMethod http://127.0.0.1:11435/api/tags
docs/CHECKLIST.md:389:  Invoke-RestMethod http://192.168.0.189:11434/api/tags
docs/CHECKLIST.md:391:- **Factual results:** Ollama listener inspection showed exactly `127.0.0.1:11435`; direct backend health returned four models. Caddy validation returned `Valid configuration`; Caddy listener inspection showed exactly `192.168.0.189:11434`; Caddy administration was disabled. Local proxy health succeeded and proxied `/api/tags` returned four models.
docs/CHECKLIST.md:434:- **Factual results:** Caddy static validation succeeded with strict SNI/Host enforcement enabled for client authentication. During the approved temporary test, Ollama listened only on `127.0.0.1:11435` and the verifier only on `127.0.0.1:11436`; direct Kali connections to those backend ports timed out. A valid mTLS request without a Bearer credential returned HTTP `401`. The verifier recorded an allow decision when the configured Bearer credential was supplied.
docs/CHECKLIST.md:436:- **Dependencies / limitations:** The server certificate was reissued under the existing private CA with `DNS:ollama-mtls.home.arpa` and `IP:192.168.0.189` SANs to align Caddy strict SNI/Host enforcement with the test hostname. The authenticated request crossed the Kali-to-Windows boundary and is documented under P00-009.
docs/CHECKLIST.md:499:- **Factual results:** The analysis input was `ubuntu-server_P00-013_20261003T055707Z_working.elf`, size `4,317,911,540` bytes, SHA-256 `e5184b85d82f1abb130fc726afecadc7f9b0c298f60b54be1dc6b3b487816f93`. Banner validation exited `0` at `2026-10-03T06:30:47Z`; `linux.pslist` exited `0` at `2026-10-03T06:44:50Z`; and `linux.pstree` exited `0` at `2026-10-03T06:46:14Z`. The Linux process plugins used `Ubuntu_6.8.0-90-generic_6.8.0-90.91_amd64.json.xz`, verified by symbol Git blob SHA-1 `cc2757b589e0af49fde532fc05a4c038c3b4a461`. The observed process list and parent/child hierarchy were plausible for the configured disposable Ubuntu lab host.
docs/CHECKLIST.md:708:- **Runtime and provisioning:** The job uses `node:24.19.0-bookworm-slim` on the existing `soc-docker` runner tag. It runs `npm ci --ignore-scripts --no-audit --fund=false` from the committed lockfile to provision the ignored TypeScript dependency tree. This is controlled CI bootstrap provisioning; the ingestion verifier itself reads only the checked-out local repository.
docs/CHECKLIST.md:790:- **Mythril identity:** v0.24.8, `mythril/myth@sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff`.
docs/CHECKLIST.md:974:| P04-003 | Implement `scripts/enrich-findings.mts` mappings for ATT&CK, CIS, ISO 27001, and CSET. | ✅ | Complete and verified 2026-10-08: `enrichFindings` and `mapFindingToGovernance` implemented for MITRE ATT&CK, CIS Controls v8, ISO/IEC 27001:2022, and CSET; 5 unit assertions passed, strict manifest ingestion valid, 10 storage tests passed, and 83 Hardhat regression tests passed. |
docs/CHECKLIST.md:980:| P04-009 | Deploy MCP middleware pool in Docker Compose. | ✅ | Complete and verified 2026-10-08: `docker-compose.test.yml` deployed and validated covering `mcp-storage`, `mcp-anvil`, `mcp-forensics` (read-only), and `mcp-telemetry` under unprivileged execution (1000:1000) and isolated network; 20 MCP tests passed, 14 storage tests passed, 7 agent tests passed, strict manifest ingestion valid, and 83 Hardhat regression tests passed. |
docs/CHECKLIST.md:1084:| P08-001 | Deploy Prometheus plus ELK, or document Grafana/Loki lightweight replacement. | ✅ | Complete and verified 2026-10-10: Configured dual observability architecture in `docs/OBSERVABILITY_STACK.md` and scrape targets in `config/telemetry/prometheus.blockchain-soc.yml`; implemented `src/observability/telemetry_stack.py` supporting both full enterprise ELK profile (`:9090`, `:9200`, `:5601`) and lightweight Grafana/Loki replacement profile (`:9090`, `:3100`, `:3000`); verified live running Docker host services (Prometheus 200, Elasticsearch 401, Kibana 200, Grafana 200); 10 observability unit tests passed, 29 deployment tests passed, 39 consensus tests passed, 42 agent tests passed, 14 LLM client tests passed, 18 storage tests passed, 20 MCP tests passed, strict manifest ingestion valid, and 83 Hardhat regression tests passed. |
docs/CHECKLIST.md:1085:| P08-002 | Implement real Prometheus and ELK telemetry query functions. | ✅ | Complete and verified 2026-10-10: Implemented `src/observability/telemetry_client.py` containing `PrometheusQueryClient` (instant queries `/api/v1/query`, range queries `/api/v1/query_range`, scalar gauge extraction), `ElasticsearchQueryClient` (DSL search queries `/_search`, document indexing `/_doc`, security event filtering by finding ID and category, basic auth header injection), and `SOCTelemetryClient` (unified metrics snapshot compilation and security event correlation); verified live queries against host Prometheus (:9090); 19 observability unit tests passed, 29 deployment tests passed, 39 consensus tests passed, 42 agent tests passed, 14 LLM client tests passed, 18 storage tests passed, 20 MCP tests passed, strict manifest ingestion valid, and 83 Hardhat regression tests passed. |
src/agents/upgrade5_defi_attacks.py:101:                            "method_selector": calldata_a[:10] if len(calldata_a) >= 10 else calldata_a,
src/agents/agent_c_compliance_judge.py:47:        "details": response_text[:250].strip(),
scripts/sync-defectdojo-metrics.py:33:VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/sync-defectdojo-metrics.py:35:URL = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8085") + "/api/v2"
scripts/sync-defectdojo-metrics.py:122:    thehive_url = os.environ.get("THEHIVE_URL", "http://127.0.0.1:9005")
scripts/sync-defectdojo-metrics.py:151:    thehive_url = os.environ.get("THEHIVE_URL", "http://127.0.0.1:9005")
scripts/generate-html-report.mts:174:               <div class="infra-name" style="font-size:12px;">L${a.level} · ${escapeHtml(a.name)}</div>
scripts/generate-html-report.mts:180:        <div class="section-card" style="margin-bottom:10px;">
scripts/generate-html-report.mts:182:            <div class="section-title" style="margin-bottom:0; font-size:14px;">${escapeHtml(sub)}</div>
scripts/generate-html-report.mts:214:        <p style="font-size:13px; color:#cbd5e1; margin-top:14px;">Assessed this run — real pass/fail evidence, with the subdimension's claimed level capped below any failed activity:</p>
scripts/generate-html-report.mts:217:        <p style="font-size:13px; color:#cbd5e1; margin-top:18px;">Not assessed — no tooling in this pipeline can check these; they require manual or organizational evidence (e.g. security champions programs, training records, threat-modeling process, access reviews):</p>
scripts/generate-html-report.mts:343:      <td class="finding-cell"><b>${escapeHtml(f.title)}</b><div class="dim" style="font-size:12px; margin-top:2px;">${escapeHtml(f.description)}</div></td>
scripts/generate-html-report.mts:568:    .badge { display:inline-block; padding:2px 9px; border-radius:5px; font-size:10.5px; font-weight:700; letter-spacing:0.2px; white-space: nowrap; }
scripts/generate-html-report.mts:685:          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Severity Breakdown</div><div class="chart-box"><canvas id="chartSeverity"></canvas></div></div>
scripts/generate-html-report.mts:686:          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Findings by Zone</div><div class="chart-box"><canvas id="chartZone"></canvas></div></div>
scripts/generate-html-report.mts:687:          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Gate Status by Policy</div><div class="chart-box"><canvas id="chartGates"></canvas></div></div>
scripts/generate-html-report.mts:688:          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Run History Trend</div><div class="chart-box"><canvas id="chartTrend"></canvas></div></div>
scripts/generate-html-report.mts:753:          <div class="infra-detail" style="text-align:left; max-width:100%; margin-bottom:6px;">${escapeHtml(v104.hashicorp_vault?.detail || "")}</div>
scripts/generate-html-report.mts:758:          <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(v104.k3s_kubernetes?.node || "")} ${escapeHtml(v104.k3s_kubernetes?.version || "")} ${escapeHtml(v104.k3s_kubernetes?.detail || "")}</div>
scripts/generate-html-report.mts:762:          <p style="font-size:13px; color:#cbd5e1;">Categories actually triggered this run:</p>
scripts/generate-html-report.mts:769:          <div class="infra-row" style="margin-top:14px;">
scripts/generate-html-report.mts:773:          <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(v104.openscap?.standard || "")}</div>
scripts/generate-html-report.mts:805:        <details class="collapsible" style="margin-top:16px;">
src/llm_client/ollama_client.py:19:    "A": "qwen2.5-coder:32b",
src/llm_client/ollama_client.py:20:    "B": "deepseek-r1:32b-stable",
src/llm_client/ollama_client.py:21:    "C": "qwen3:32b",
src/llm_client/ollama_client.py:22:    "D": "deepseek-r1:32b-stable",
src/llm_client/ollama_client.py:24:    "F": "deepseek-r1:32b-stable",
src/llm_client/ollama_client.py:25:    "G": "qwen2.5-coder:32b",
src/llm_client/ollama_client.py:29:    "A": "qwen2.5-coder:14b",
src/llm_client/ollama_client.py:30:    "B": "deepseek-r1:14b",
src/llm_client/ollama_client.py:31:    "C": "qwen2.5:14b",
src/llm_client/ollama_client.py:32:    "D": "deepseek-r1:14b",
src/llm_client/ollama_client.py:33:    "E": "qwen2.5:14b",
src/llm_client/ollama_client.py:34:    "F": "deepseek-r1:14b",
src/llm_client/ollama_client.py:66:    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").strip()
src/llm_client/ollama_client.py:108:    resolved_model = model or routing.get(resolved_agent, "qwen2.5-coder:32b")
src/llm_client/ollama_client.py:192:    assigned_model = routing.get(agent, "qwen2.5-coder:32b")
scripts/pipeline-verdict.py:103:        print(f"    {({'ok': '[+]', 'not_run': '[!]', 'error': '[-]'}.get(s, '[?]'))} {n:<12} {s:<8} {p:<8} {d[:90]}")
scripts/exporter-daemon.py:29:    print("[+] [PROMETHEUS EXPORTER DAEMON] Serving metrics on http://0.0.0.0:9101/metrics...")
scripts/aggregate-infra-status.py:48:                "host_bridge": "http://192.168.0.189:11434",
src/forensics/stix_exporter.py:72:                "name": f"Flagged address ({attacker_or_flagged_address[:10]}...)",
scripts/lib/thehive_case.py:102:    host = os.getenv("OLLAMA_BASE_URL", os.getenv("OLLAMA_HOST", "http://192.168.0.189:11434"))
scripts/run-openscap-audit.py:73:    version = ver[0][:80] if ver else None
src/compliance/graph_integrator.py:51:                "finding_id": f"FINDING-COMPLIANCE-SCREEN-{match.matched_address[:10]}",
src/observability/telemetry_client.py:47:    def __init__(self, base_url: str = "http://localhost:9090", timeout: float = 3.0):
src/observability/telemetry_client.py:105:        base_url: str = "http://localhost:9200",
src/observability/telemetry_client.py:184:        prometheus_url: str = "http://localhost:9090",
src/observability/telemetry_client.py:185:        elasticsearch_url: str = "http://localhost:9200",
scripts/run-dast.sh:4:# Override: DAST_TARGET=http://127.0.0.1:PORT   or   DAST_SERVE_DIR=some/dir
scripts/run-dast.sh:18:  TARGET="http://127.0.0.1:$PORT"
scripts/bootstrap-langfuse.py:107:LANGFUSE_HOST="http://127.0.0.1:3100"
docker/docker-compose.validators.yml:16:      - "8081:8081"
docker/docker-compose.validators.yml:20:      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8081/health', timeout=2)"]
docker/docker-compose.validators.yml:38:      - "8082:8082"
docker/docker-compose.validators.yml:42:      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8082/health', timeout=2)"]
docker/docker-compose.validators.yml:60:      - "8083:8083"
docker/docker-compose.validators.yml:64:      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8083/health', timeout=2)"]
scripts/ship-siem-telemetry.py:69:    es_url = os.getenv("ELASTICSEARCH_URL", "http://127.0.0.1:9200/blockchain-soc-audit-logs/_doc")
scripts/ship-siem-telemetry.py:96:            print(f"[-] [SIEM ELASTICSEARCH] HTTP {res.status_code}: {res.text[:120]}")
scripts/ship-siem-telemetry.py:146:        _tool_status_line("HashiCorp Vault", "http://127.0.0.1:8200",
scripts/ship-siem-telemetry.py:149:        _tool_status_line("SonarQube SAST", "http://127.0.0.1:9000",
scripts/ship-siem-telemetry.py:152:        _tool_status_line("Jenkins Enterprise", "http://127.0.0.1:8082",
scripts/ship-siem-telemetry.py:157:        _tool_status_line("LangGraph Swarm", "192.168.0.189:11434",
scripts/ship-siem-telemetry.py:160:        _tool_status_line("Anvil AVS Consensus", ":8545, :8546, :8547",
scripts/ship-siem-telemetry.py:164:        _tool_status_line("Elasticsearch SIEM", "http://127.0.0.1:9200",
scripts/ship-siem-telemetry.py:252:        print("[+] [PROMETHEUS LISTENER] Metrics endpoint listening on http://0.0.0.0:9101/metrics")
scripts/ingest-defectdojo.py:32:DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://127.0.0.1:8085")
test/consensus/test_validator_cluster.py:35:        url = f"http://127.0.0.1:{self.port}/health"
test/consensus/test_validator_cluster.py:44:        url = f"http://127.0.0.1:{self.port}/vote"
test/consensus/test_validator_cluster.py:60:        url = f"http://127.0.0.1:{self.port}/nonexistent"
test/deployment/test_gitlab_mr_workflow.py:29:            synthesizedAt="2026-10-10T00:00:00+00:00",
test/deployment/test_forensic_staging_snapshot.py:26:            "logs/job_run.log": b"[2026-10-10 07:00:00] Run initiated\n[2026-10-10 07:00:01] Complete\n",
docs/FORENSIC_WALKTHROUGH_SCRIPT.md:5:**Target Duration:** 2:00 – 2:45 minutes  
docs/FORENSIC_WALKTHROUGH_SCRIPT.md:10:### Scene 1: Order of Volatility & Acquisition (0:00 – 0:45)
docs/FORENSIC_WALKTHROUGH_SCRIPT.md:19:### Scene 2: Merkle Sealing & Append-Only Hash Chains (0:45 – 1:35)
docs/FORENSIC_WALKTHROUGH_SCRIPT.md:30:### Scene 3: Verification Proof & Empirical Forensic Metrics (1:35 – 2:30)
docs/RUNBOOK.md:433:- Mythril runs from local Docker image `mythril/myth:latest`, validated at image digest `sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff`.
docs/RUNBOOK.md:508:- `docker pull mythril/myth:latest` completed; image inspection returned digest `sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff`.
docs/RUNBOOK.md:654:- Bind Ollama only to `127.0.0.1:11435`.
docs/RUNBOOK.md:655:- Bind Caddy only to `192.168.0.189:11434`.
docs/RUNBOOK.md:662:Create a host-local Caddyfile outside the repository with automatic HTTPS and Caddy administration disabled, an explicit `bind 192.168.0.189`, and a `reverse_proxy 127.0.0.1:11435` site at `http://192.168.0.189:11434`. Validate it with:
docs/RUNBOOK.md:670:1. In a normal-user PowerShell session, set process-local `OLLAMA_HOST` to `127.0.0.1:11435` and process-local `OLLAMA_MODELS` to the existing approved host-local model store, then run `ollama.exe serve`.
docs/RUNBOOK.md:671:2. Confirm startup output reports `Listening on 127.0.0.1:11435`.
docs/RUNBOOK.md:678:4. Confirm Caddy reports that its administration endpoint is disabled and its HTTP listener is `192.168.0.189:11434`.
docs/RUNBOOK.md:683:Invoke-RestMethod http://127.0.0.1:11435/api/tags
docs/RUNBOOK.md:685:Invoke-RestMethod http://192.168.0.189:11434/api/tags
docs/RUNBOOK.md:689:- Listener inspection showed Ollama solely at `127.0.0.1:11435` and Caddy solely at `192.168.0.189:11434`.
docs/RUNBOOK.md:692:**Expected healthy result:** Direct backend health and private-interface proxy health each return four models. Ollama is not a private-interface listener; Caddy is the sole listener at `192.168.0.189:11434`.
docs/RUNBOOK.md:697:- If Caddy appears on `[::]:11434`, stop it and use an explicit `bind 192.168.0.189` directive before retesting.
docs/RUNBOOK.md:720:  -> https://ollama-mtls.home.arpa:11434
docs/RUNBOOK.md:722:  -> loopback-only forward-auth verifier at 127.0.0.1:11436
docs/RUNBOOK.md:723:  -> loopback-only Ollama backend at 127.0.0.1:11435
docs/RUNBOOK.md:728:- Server certificate identity was aligned with the Caddy site name using `DNS:ollama-mtls.home.arpa` and `IP:192.168.0.189`.
docs/RUNBOOK.md:779:- Preserve Ollama loopback binding at `127.0.0.1:11435`; do not expose Ollama directly to the LAN.
docs/RUNBOOK.md:803:- Caddy reverse-proxies only to `127.0.0.1:11435`.
docs/RUNBOOK.md:1847:Validate mapping of normalized security findings to cybersecurity governance frameworks: MITRE ATT&CK, CIS Controls v8, ISO/IEC 27001:2022, and CSET.
docs/pipeline-source-dump-1.md:973:    print(f'    -> Simulation approved: digest={receipt.receipt_digest[:16]}... gas_used={receipt.gas_used} success={receipt.success}')
docs/pipeline-source-dump-1.md:977:                 detail=f'digest={receipt.receipt_digest[:16]}... success={receipt.success}')
docs/pipeline-source-dump-1.md:981:                 detail=f'rejected: {str(e)[:150]}')
docs/pipeline-source-dump-1.md:989:addr = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
docs/pipeline-source-dump-1.md:1001:            write_result('vault-sign', 'vault-transit', 'ok', detail='signature ' + sig[:24] + '...')
docs/pipeline-source-dump-1.md:1005:        write_result('vault-sign', 'vault-transit', 'error', detail=str(e)[:120])
docs/pipeline-source-dump-1.md:1042:    write_result('k3s', 'kubectl', 'not_run', detail=str(e)[:150])
docs/pipeline-source-dump-1.md:1065:print(f'    -> Forensic record sealed: {rec[\"evidence_id\"]} | {seal[\"file_count\"]} files | Hash: {rec[\"sha256\"][:16]}...')
docs/pipeline-source-dump-1.md:1106:        VAULT_ADDR = 'http://192.168.0.150:8200'
docs/pipeline-source-dump-1.md:1130:                      -Dsonar.host.url="http://127.0.0.1:9000" \
docs/pipeline-source-dump-1.md:1182:  VAULT_ADDR: "http://172.17.0.1:8200"
docs/pipeline-source-dump-1.md:1184:  JENKINS_ADDR: "http://172.17.0.1:8082"
docs/pipeline-source-dump-1.md:1189:  ARGOCD_ADDR: "https://172.17.0.1:31703"
docs/pipeline-source-dump-1.md:1208:  image: node:24.19.0-bookworm-slim
docs/pipeline-source-dump-1.md:1232:  image: node:24.19.0-bookworm-slim
docs/pipeline-source-dump-1.md:1247:  image: node:24.19.0-bookworm-slim
docs/pipeline-source-dump-1.md:2146:        return _res("error", f"slither reported failure: {str(data.get('error'))[:200]}")
docs/pipeline-source-dump-1.md:2212:                return _res("error", f"mythril reported failure: {str(out.get('error'))[:200]}")
src/agents/graph.py:78:    graph.add_node("agent_a_auditor", audit_contract_node, model_tag="qwen2.5-coder:32b")
src/agents/graph.py:79:    graph.add_node("agent_b_threat_hunter", threat_hunter_node, model_tag="deepseek-r1:32b")
src/agents/graph.py:80:    graph.add_node("agent_c_compliance_judge", compliance_judge_node, model_tag="qwen2.5:32b")
src/agents/graph.py:81:    graph.add_node("agent_d_red_teamer", red_teamer_node, model_tag="deepseek-r1:32b")
src/agents/graph.py:82:    graph.add_node("agent_e_incident_commander", incident_commander_node, model_tag="qwen2.5:32b")
src/agents/graph.py:83:    graph.add_node("agent_f_deep_logic", logic_analyzer_node, model_tag="deepseek-r1:32b")
src/agents/graph.py:84:    graph.add_node("agent_g_guardrail", guardrail_watchdog_node, model_tag="qwen2.5:32b")
src/agents/agent_d_red_teamer.py:56:        "details": response_text[:200] if response_text else "No details extracted.",
scripts/notify-slack.py:8:VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/bootstrap-thehive-enterprise.py:8:BASE = "http://127.0.0.1:9005"
scripts/bootstrap-thehive-enterprise.py:81:        dtype, dval = obs["dataType"], obs["data"][:32]
scripts/orchestrate-enterprise-integrations.sh:10:VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
scripts/orchestrate-enterprise-integrations.sh:11:JENKINS_ADDR="${JENKINS_ADDR:-http://127.0.0.1:8082}"
scripts/orchestrate-enterprise-integrations.sh:58:    "{\"data\":{\"token\":\"${DEFECTDOJO_TOKEN}\",\"url\":\"${DEFECTDOJO_URL:-http://127.0.0.1:8085}\"}}" token
scripts/orchestrate-enterprise-integrations.sh:85:  if [ -n "$SIG" ]; then RES vault hashicorp-vault ok --detail "healthy, unsealed; transit signing works (${SIG:0:24}...)"
scripts/run-sast-symbolic.py:62:        return _res("error", f"slither reported failure: {str(data.get('error'))[:200]}")
scripts/run-sast-symbolic.py:128:                return _res("error", f"mythril reported failure: {str(out.get('error'))[:200]}")
deploy/thehive/docker-compose.yml:7:      - "9005:9000"
src/consensus/avs_consensus.py:100:        self.rpc = f"http://127.0.0.1:{port}"
src/consensus/avs_consensus.py:135:            raise ToolingError(f"deploy {name} failed: {(err or out).strip()[:200]}")
src/consensus/avs_consensus.py:146:            raise ToolingError(f"victim deposit failed: {err.strip()[:200]}")
src/consensus/avs_consensus.py:235:        raise ToolingError(f"forge build failed: {(err or out).strip()[:300]}")
src/consensus/avs_consensus.py:274:            print(f"    [*] node {obs['node_id']} ({obs['validator']}) vault={obs['vault_address'][:10]}... "
src/consensus/avs_consensus.py:279:                            target=target_src, detail=str(exc)[:250],
scripts/run-formal-tools.cjs:13:const IMAGE = "mythril/myth@sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff";
scripts/notify-gmail.py:48:                  (f" - {(_r.get('detail') or '')[:100]}" if _r.get("status") != "ok" else ""))
config/k8s/argocd-app.yaml:11:    repoURL: 'ssh://git@192.168.0.150:2222/root/blockchain-security-project-remastered.git'
src/agents/agent_b_threat_hunter.py:32:        "TIMESTAMP=2026-10-08T12:00:00Z EVENT=TRANSACTION_EXECUTION "
src/agents/agent_b_threat_hunter.py:74:        "details": response_text[:250].strip(),
src/agents/agent_e_incident_commander.py:62:        "rationale": response_text[:200] if response_text else "No analysis available.",
src/wallet/mpc_joint_signer.py:138:        r = int.from_bytes(packed_sig[:32], byteorder="big")
src/wallet/mpc_joint_signer.py:139:        s = int.from_bytes(packed_sig[32:64], byteorder="big")
src/wallet/mpc_relayer_cluster.py:25:        return f"04{self.pub_x:064x}{self.pub_y:064x}"
src/wallet/mpc_relayer_cluster.py:36:        return f"04{self.pub_x:064x}{self.pub_y:064x}"
src/wallet/mpc_relayer_cluster.py:154:        pub_bytes = bytes.fromhex(f"{joint_x:064x}{joint_y:064x}")
src/consensus/avs_gate.py:63:        resolved_nonce = nonce or hashlib.sha256(f"{finding_id}:{ts}".encode("utf-8")).hexdigest()[:16]
src/mcp_middleware/host_forensics.py:127:        #       002:  000:000   0000002048  0000206847  0000204800  Linux (0x83)
scripts/run-ofac-screening.py:48:        return write_result("ofac-screening", "ofac-sdn", "not_run", detail=str(exc)[:200])
scripts/run-ofac-screening.py:65:        return write_result("ofac-screening", "ofac-sdn", "error", detail=str(exc)[:200])
scripts/provision-thehive-vault.py:9:THEHIVE = "http://127.0.0.1:9005"
scripts/provision-thehive-vault.py:10:VAULT = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/provision-thehive-vault.py:94:            print(f"    -> Indexed: [{obs['dataType']}] {obs['data'][:28]}...")
src/deployment/consensus_deployer.py:75:        rpc_url: str = "http://127.0.0.1:8545",
src/deployment/consensus_deployer.py:118:            deployer_address = "0x" + hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:40]
src/deployment/consensus_deployer.py:125:        deploy_salt = f"{plan_digest}:{certificate.aggregate_signature[:16]}:{deployer_address}"
src/deployment/consensus_deployer.py:126:        contract_addr = "0x" + hashlib.sha256(f"contract:{deploy_salt}".encode("utf-8")).hexdigest()[:40]
src/observability/shadow_fork_verifier.py:30:    rpc_url: str = "http://127.0.0.1:8545"
src/observability/threat_intel.py:59:                    "flagged": None, "detail": str(exc)[:120]}
src/observability/threat_intel.py:86:    print(f"[+] OFAC screen {demo[:12]}...: status={res['status']} "
scripts/run-incident-abort.py:88:        print(f"    [-] evidence DB seal warning: {str(exc)[:100]}")
scripts/run-incident-abort.py:90:          f"root SHA-256: {seal['root_sha256'][:24]}...")
scripts/run-incident-abort.py:136:        print(f"    [-] TheHive stderr: {proc.stderr.strip()[:200]}")
scripts/ingest-thehive-incident.py:22:THEHIVE_BASE = os.environ.get("THEHIVE_BASE", os.environ.get("THEHIVE_URL", "http://127.0.0.1:9005"))
scripts/ingest-thehive-incident.py:24:VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/ingest-thehive-incident.py:122:        print(f"[-] [THEHIVE] unreachable: {str(exc)[:150]}")
scripts/ingest-thehive-incident.py:123:        write_result("thehive", "thehive", "error", detail=f"unreachable: {str(exc)[:150]}")
scripts/ingest-thehive-incident.py:126:        print(f"[-] [THEHIVE] case creation failed: HTTP {res.status_code} {res.text[:200]}")
scripts/ingest-thehive-incident.py:128:                     detail=f"case creation failed: HTTP {res.status_code} {res.text[:200]}")
scripts/langfuse_tracer.py:48:    host = env.get("LANGFUSE_HOST", "http://127.0.0.1:3100")
scripts/langfuse_tracer.py:234:            write_result("langfuse", "langfuse", "error", detail=f"HTTP {r.status_code}: {r.text[:200]}")
scripts/langfuse_tracer.py:237:        write_result("langfuse", "langfuse", "error", detail=f"stream error: {str(err)[:200]}")
scripts/ingest-granular-siem.py:21:ELASTIC_URL = os.getenv("ELASTICSEARCH_URL", "http://192.168.0.150:9200")
scripts/ingest-granular-siem.py:137:                        "message": alert.get("desc")[:250] if alert.get("desc") else "DAST finding"
scripts/run-sonar.sh:8:SONAR_ADDR="${SONAR_ADDR:-http://127.0.0.1:9000}"
scripts/run-sonar.sh:10:VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
scripts/vault-hive-pipeline.py:11:THEHIVE = "http://127.0.0.1:9005"
scripts/vault-hive-pipeline.py:12:VAULT = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
scripts/vault-hive-pipeline.py:197:            print(f"    -> Indexed observable: [{obs['dataType']}] {obs['data'][:28]}...")
config/env.example:9:OLLAMA_HOST=http://127.0.0.1:11434
scripts/run-all-e2e.sh:185:    print(f'    -> Simulation approved: digest={receipt.receipt_digest[:16]}... gas_used={receipt.gas_used} success={receipt.success}')
scripts/run-all-e2e.sh:189:                 detail=f'digest={receipt.receipt_digest[:16]}... success={receipt.success}')
scripts/run-all-e2e.sh:193:                 detail=f'rejected: {str(e)[:150]}')
scripts/run-all-e2e.sh:201:addr = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
scripts/run-all-e2e.sh:213:            write_result('vault-sign', 'vault-transit', 'ok', detail='signature ' + sig[:24] + '...')
scripts/run-all-e2e.sh:217:        write_result('vault-sign', 'vault-transit', 'error', detail=str(e)[:120])
scripts/run-all-e2e.sh:254:    write_result('k3s', 'kubectl', 'not_run', detail=str(e)[:150])
scripts/run-all-e2e.sh:277:print(f'    -> Forensic record sealed: {rec[\"evidence_id\"]} | {seal[\"file_count\"]} files | Hash: {rec[\"sha256\"][:16]}...')
scripts/export-env.sh.example:7:export OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"
```

---

## Part 3 — Running vs. referenced-only, checked live

Raw evidence first, then the service-by-service table.

### `docker ps` (live, just run)

```
NAMES                       IMAGE                                                         PORTS
soc-thehive-enterprise      thehiveproject/thehive4:4.1.24-1                              0.0.0.0:9005->9000/tcp, [::]:9005->9000/tcp
langfuse-server             ghcr.io/langfuse/langfuse:2                                   0.0.0.0:3100->3000/tcp, [::]:3100->3000/tcp
langfuse-postgres           postgres:15-alpine                                            5432/tcp
defectdojo-nginx-1          registry.defectdojo.com/defectdojo/defectdojo-nginx:latest    80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp, 0.0.0.0:8085->8080/tcp
defectdojo-celeryworker-1   registry.defectdojo.com/defectdojo/defectdojo-django:latest   
defectdojo-uwsgi-1          registry.defectdojo.com/defectdojo/defectdojo-django:latest   
defectdojo-celerybeat-1     registry.defectdojo.com/defectdojo/defectdojo-django:latest   
defectdojo-postgres-1       postgres:18.6-alpine                                          5432/tcp
defectdojo-valkey-1         valkey/valkey:9.1.2-alpine                                    6379/tcp
cross-vault                 hashicorp/vault:1.15.6                                        0.0.0.0:8200->8200/tcp, [::]:8200->8200/tcp
cross-gitlab-runner         gitlab/gitlab-runner:alpine                                   
cross-kibana                docker.elastic.co/kibana/kibana:8.11.0                        
cross-elasticsearch         docker.elastic.co/elasticsearch/elasticsearch:8.11.0          
cross-grafana               grafana/grafana:10.4.0                                        
cross-prometheus            prom/prometheus:v2.51.0                                       
cross-node-exporter         quay.io/prometheus/node-exporter:v1.7.0                       
cross-gitlab                gitlab/gitlab-ce:16.11.0-ce.0                                 80/tcp, 443/tcp, 0.0.0.0:8929->8929/tcp, [::]:8929->8929/tcp, 0.0.0.0:2222->22/tcp, [::]:2222->22/tcp
cross-jenkins               jenkins/jenkins:lts                                           0.0.0.0:50000->50000/tcp, [::]:50000->50000/tcp, 0.0.0.0:8082->8080/tcp, [::]:8082->8080/tcp
cross-sonarqube             sonarqube:lts-community                                       0.0.0.0:9000->9000/tcp, [::]:9000->9000/tcp
```

### `ss -tlnp` (live, just run -- all actual listening TCP sockets on this host)

```
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      4096         0.0.0.0:8929       0.0.0.0:*   
LISTEN 0      5            0.0.0.0:9101       0.0.0.0:*    users:(("python3",pid=8026,fd=3))
LISTEN 0      4096         0.0.0.0:9005       0.0.0.0:*   
LISTEN 0      4096         0.0.0.0:9000       0.0.0.0:*   
LISTEN 0      4096         0.0.0.0:8443       0.0.0.0:*   
LISTEN 0      4096         0.0.0.0:8200       0.0.0.0:*   
LISTEN 0      4096       127.0.0.1:6444       0.0.0.0:*   
LISTEN 0      4096       127.0.0.1:10010      0.0.0.0:*   
LISTEN 0      4096         0.0.0.0:50000      0.0.0.0:*   
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*   
LISTEN 0      511        127.0.0.1:41943      0.0.0.0:*    users:(("code",pid=395908,fd=40))
LISTEN 0      4096         0.0.0.0:3100       0.0.0.0:*   
LISTEN 0      4096       127.0.0.1:10248      0.0.0.0:*   
LISTEN 0      4096       127.0.0.1:10249      0.0.0.0:*   
LISTEN 0      4096       127.0.0.1:10258      0.0.0.0:*   
LISTEN 0      4096       127.0.0.1:10259      0.0.0.0:*   
LISTEN 0      4096       127.0.0.1:10256      0.0.0.0:*   
LISTEN 0      4096       127.0.0.1:10257      0.0.0.0:*   
LISTEN 0      4096         0.0.0.0:2222       0.0.0.0:*   
LISTEN 0      511          0.0.0.0:5601       0.0.0.0:*    users:(("node",pid=5254,fd=69))
LISTEN 0      4096         0.0.0.0:8085       0.0.0.0:*   
LISTEN 0      4096         0.0.0.0:8080       0.0.0.0:*   
LISTEN 0      4096         0.0.0.0:8082       0.0.0.0:*   
LISTEN 0      4096               *:9300             *:*   
LISTEN 0      4096            [::]:8929          [::]:*   
LISTEN 0      4096               *:9090             *:*   
LISTEN 0      4096               *:9100             *:*   
LISTEN 0      4096               *:9200             *:*   
LISTEN 0      4096            [::]:9005          [::]:*   
LISTEN 0      4096            [::]:9000          [::]:*   
LISTEN 0      4096            [::]:8443          [::]:*   
LISTEN 0      4096            [::]:8200          [::]:*   
LISTEN 0      4096               *:10250            *:*   
LISTEN 0      4096            [::]:50000         [::]:*   
LISTEN 0      128             [::]:22            [::]:*   
LISTEN 0      4096            [::]:3100          [::]:*   
LISTEN 0      4096               *:3000             *:*   
LISTEN 0      4096            [::]:2222          [::]:*   
LISTEN 0      4096            [::]:8082          [::]:*   
LISTEN 0      4096               *:6443             *:*   
```

### Service-by-service

Several containers (`cross-kibana`, `cross-elasticsearch`, `cross-grafana`,
`cross-prometheus`, `cross-node-exporter`) run with `--network host`, so
`docker ps` shows no published-port mapping for them -- their real port is
only visible in the `ss -tlnp` output, cross-referenced below.

| Service | Real port | Status |
|---|---|---|
| HashiCorp Vault | 8200 | **Running** -- `cross-vault` container, confirmed in both `docker ps` and `ss` |
| Jenkins (web) | 8082 | **Running** -- `cross-jenkins`, confirmed in both |
| Jenkins (agent) | 50000 | **Running** -- `cross-jenkins`, confirmed in both |
| SonarQube | 9000 | **Running** -- `cross-sonarqube`, confirmed in both |
| TheHive | 9005 | **Running** -- `soc-thehive-enterprise` (deployed from `deploy/thehive/docker-compose.yml`, whose `container_name`/image/port match exactly), confirmed in both |
| Langfuse (web) | 3100 | **Running** -- `langfuse-server`, confirmed in both (container's internal port 3000, published as 3100) |
| DefectDojo (nginx, HTTP) | 8085 | **Running** -- `defectdojo-nginx-1`, confirmed in both |
| DefectDojo (nginx, HTTPS) | 8443 | **Running** -- same container, confirmed in both |
| GitLab (web) | 8929 | **Running** -- `cross-gitlab`, confirmed in both |
| GitLab (SSH) | 2222 | **Running** -- `cross-gitlab`, confirmed in both |
| Grafana | 3000 | **Running**, host-network (not shown in `docker ps`) -- confirmed via `ss` (`*:3000` listening) **and** a live `GET /api/health` returning `"version": "10.4.0"`, matching the `cross-grafana` image tag exactly |
| Prometheus | 9090 | **Running**, host-network -- confirmed via `ss` **and** `config/telemetry/prometheus.blockchain-soc.yml`'s own self-scrape target `localhost:9090` |
| node_exporter | 9100 | **Running**, host-network -- confirmed via `ss` **and** the same prometheus.yml's `node_exporter` job targets |
| This project's own telemetry exporter (`ship-siem-telemetry.py`'s HTTP server) | 9101 | **Running** -- confirmed via `ss`, which shows the listening process literally as `python3` |
| Elasticsearch (HTTP) | 9200 | **Running**, host-network -- confirmed via `ss` |
| Elasticsearch (transport) | 9300 | **Running**, host-network -- confirmed via `ss` |
| Kibana | 5601 | **Running**, host-network -- confirmed via `ss` (listening process shown as `node`) |
| K3s API server | 6443 | **Running** -- confirmed via `ss` (part of the K3s cluster this project's ArgoCD GitOps flow deploys to, not a service this repo defines itself) |
| K3s supervisor | 6444 (127.0.0.1 only) | **Running** -- confirmed via `ss` |
| K3s kubelet/controller-manager/scheduler/proxy internals | 10010, 10248, 10249, 10250, 10256-10259 | **Running** -- confirmed via `ss`; not application-level dashboards, listed for completeness since they matched the sweep |
| ArgoCD | 31703 (NodePort, HTTPS) | **Running and reachable** -- confirmed via a live `curl -k https://127.0.0.1:31703` returning HTTP 200. Note: this NodePort does **not** show up as a classic `LISTEN` entry in `ss -tlnp`'s output above (k3s/kube-proxy's iptables-based NodePort redirection doesn't always create one) -- the HTTP check is the real confirmation here, not `ss`. |
| Ollama | 11434 | **Reachable, but not running on this machine.** `127.0.0.1:11434` is unreachable (connection refused); `192.168.0.189:11434` returns a real `HTTP 200` from `/api/tags`. This is the real LAN inference host (confirmed in `src/agents/swarm_orchestrator.py`'s own `OLLAMA_BASE_URL` default), a separate machine, not something `docker ps`/`ss` on this host would ever show. |
| Redis (`docker-compose.yml`'s `redis` service) | 6379 | **Not running.** No container named anything redis-like exists (checked `docker ps -a`), and nothing listens on 6379 on this host. This compose file is a `TODO(phase-N)`-annotated skeleton stub (see its own comments), never actually deployed. (Note: DefectDojo's internal `defectdojo-valkey-1` container also uses 6379, but only inside DefectDojo's own private docker network -- not published to the host, and unrelated to this compose file.) |
| Anvil / local testnet RPC (`docker-compose.deploy.yml`, `docker-compose.test.yml`) | 8545 | **Not running.** No container exists under these compose files' service/container names (`testnet-rpc`, `bsp-testnet-rpc`, or any `mcp-*` service from `docker-compose.test.yml`); nothing listens on 8545. AVS consensus's real "Anvil" sandboxes seen in tonight's pipeline runs are spun up some other way at run time, not via these compose files. |
| `docker-compose.validators.yml` services | n/a | **Not running.** No matching containers exist under `docker ps -a`. |
| Grafana/Prometheus/node_exporter/Kibana/Elasticsearch's OWN compose definitions | n/a | Not found in any docker-compose file in this repo at all -- these five run as bare `docker run --network host ...` containers (confirmed via `docker ps`'s `cross-*` naming convention and host-network mode), not defined in version control anywhere in this project. |
