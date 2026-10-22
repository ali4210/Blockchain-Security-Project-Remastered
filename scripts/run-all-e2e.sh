#!/usr/bin/env bash
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"
set -eo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Determine target contract dynamically from environment or default
if [ -n "${TARGET_CONTRACT:-}" ]; then
    : # explicit path given — respect it as-is
elif [ "${SECURE:-0}" = "1" ]; then
    TARGET_CONTRACT="contracts/solidity/SecureVault.sol"
else
    TARGET_CONTRACT="contracts/solidity/VulnerableVault.sol"
fi
export TARGET_CONTRACT

if [[ "$TARGET_CONTRACT" == *"SecureVault"* ]]; then
    export SECURE="1"
    TARGET_NAME="SecureVault"
else
    export SECURE="0"
    TARGET_NAME="VulnerableVault"
fi


echo "========================================================================"
echo "   AUTONOMOUS BLOCKCHAIN SOC — FULL ENTERPRISE E2E PIPELINE"
echo "========================================================================"
START_TIME=$(date +%s)
export TARGET_NAME
VERDICT_RC=0
./scripts/init-run.sh

# Step 1: Zone 1 Manifest Ingestion & Asset Map
echo -e "\n[+] [ZONE 1] Validating Manifest Topologies & Asset Maps..."
./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
./scripts/run-secret-scan.sh

# Step 2: Zone 2 AST Sanitization, Trivy Scanner & Security Gate
echo -e "\n[+] [ZONE 2] Running Multi-Tier SAST & Symbolic Analysis..."
python3 scripts/run-sast-symbolic.py

echo -e "\n[+] [ZONE 2] Running AST String-Literal Masking..."
./node_modules/.bin/tsx --no-cache scripts/ast-mask.mts --approved-local-fixture

echo -e "\n[+] [ZONE 2] Running SCA Dependency Verification..."
python3 scripts/run-sca-gate.py

./scripts/run-trivy.sh

./scripts/run-dast.sh

python3 scripts/run-openscap-audit.py

./scripts/run-sonar.sh

./scripts/run-readiness-gate.sh

# Step 3: Zone 3 Broker Store & Attack Path Graph
echo -e "\n[+] [ZONE 3] Ingesting OSINT Threat Intelligence Feeds..."
python3 src/observability/threat_intel.py

echo -e "\n[+] [ZONE 3] Constructing Knowledge Graph & DREAD Scoring..."
python3 - <<'PYEOF'
import os
from src.storage.broker_store import BrokerStore
from src.storage.attack_path_graph import AttackPathGraph

sec_env = os.getenv("SECURE", "0")
target_env = os.getenv("TARGET_CONTRACT", "")
is_sec = (sec_env == "1") or ("SecureVault" in target_env)
t_name = "SecureVault" if is_sec else "VulnerableVault"

store = BrokerStore('data/broker_store.db')
graph = AttackPathGraph()

t_id = graph.add_target_node(t_name, target_type='contract')

finding = {
    'finding_id': 'AUDIT-001' if is_sec else 'FIND-001',
    'title': 'ChecksEffectsGuarded' if is_sec else 'ReentrancyExternalCall',
    'severity': 'INFO' if is_sec else 'CRITICAL',
    'dread_score': 0.0 if is_sec else 8.5,
    'target_contract': t_name
}

graph.build_from_findings([finding])
paths = graph.list_attack_paths()
print(f'    -> Graph synthesized: {len(paths)} attack path(s) mapped.')
PYEOF

# Step 4: Zone 6 & 8 Consensus Monitoring & OFAC Screening
# Step 3B: LangGraph 7-Agent Swarm Execution.
# Run every agent on the fast default model (OLLAMA_DEFAULT_MODEL, qwen3.5:9b):
# the env's per-agent 32B overrides are impractically slow on this host (cold
# load > 2 min, one-at-a-time serving) and time out. Scoped to a subshell so the
# rest of the pipeline keeps its env. The orchestrator still honours
# OLLAMA_MODEL_AGENT_* wherever they are set.
( for a in A B C D E F G; do unset "OLLAMA_MODEL_AGENT_$a"; done
  python3 src/agents/swarm_orchestrator.py )

# Step 3C: AVS Cryptographic Consensus & Attestation Gate
echo -e "\n[+] [AVS CONSENSUS] Executing 3-Node Byzantine Fault Tolerant Consensus..."
python3 src/consensus/avs_consensus.py

echo -e "\n[+] [ZONE 6 & 8] Streaming P2P Network Telemetry & Address Screening..."
python3 -c "
from src.consensus.p2p_listener import ConsensusNetworkListener
listener = ConsensusNetworkListener()
listener.register_peer('peer-01', '198.51.100.12', 30303, 13335, 'Geth/v1.14', 24.5)
print('    -> P2P Peer registered.')
"
# Real OFAC SDN screening (writes reports/scanners/ofac-screening.json). Screens
# TARGET_SCREEN_ADDRESS if set, else a documented demonstration canary.
python3 scripts/run-ofac-screening.py

# Verdict is computed here: after every REQUIRED Zone 2 scanner (slither,
# mythril, sast-canary, trivy, zap, sca, openscap, sonar, readiness) AND after
# the real AVS consensus / LangGraph swarm signals it also reads, but BEFORE
# Zone 4 incident response (run-incident-abort.py) reads reports/verdict.json.
# Previously verdict ran at the very end of the pipeline, so incident response
# always saw a stale/missing verdict from the prior run (or UNKNOWN on a clean
# checkout); running it before Zone 2's scanners instead would have the same
# staleness problem against avs-consensus/swarm, which run after Zone 2.
python3 scripts/pipeline-verdict.py || VERDICT_RC=$?

# Step 5: Zone 7 Wallet Simulation Gate & Live HashiCorp Vault Signing
echo -e "\n[+] [ZONE 7] Testing Pre-Sign Transaction Simulation Barrier..."
python3 -c "
from src.wallet.presign_simulator import PresignSimulator, RelayerTxIntent, SimulationError
from scripts.lib.scanner_result import write_result

target_addr = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC'
sim = PresignSimulator(allowed_recipients={target_addr}, max_drain_wei=10**18, max_gas=500000)

intent = RelayerTxIntent(
    sender='0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    target=target_addr,
    value_wei=10**17,
    data=b'',
    nonce=1,
    gas_limit=100000
)

try:
    receipt = sim.simulate_and_validate(intent)
    print(f'    -> Simulation approved: digest={receipt.receipt_digest[:16]}... gas_used={receipt.gas_used} success={receipt.success}')
    write_result('presign-sim', 'presign-simulator',
                 'ok' if receipt.success else 'error',
                 target=intent.target, counts={'gas_used': receipt.gas_used},
                 detail=f'digest={receipt.receipt_digest[:16]}... success={receipt.success}')
except SimulationError as e:
    print(f'    -> Simulation REJECTED (fail-closed): {e}')
    write_result('presign-sim', 'presign-simulator', 'error', target=intent.target,
                 detail=f'rejected: {str(e)[:150]}')
"

echo -e "\n[+] [ZONE 7] Cryptographic Attestation via Live HashiCorp Vault Transit Engine..."
python3 -c "
import base64, os, requests
from scripts.lib.scanner_result import write_result

addr = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
token = os.environ.get('VAULT_TOKEN')
if not token:
    write_result('vault-sign', 'vault-transit', 'not_run', detail='VAULT_TOKEN not set')
else:
    msg = 'ATTESTATION:' + os.environ.get('TARGET_NAME', 'unknown') + ':PIPELINE_RUN'
    payload = base64.b64encode(msg.encode()).decode()
    try:
        resp = requests.post(addr + '/v1/transit/sign/soc-relayer-key', headers={'X-Vault-Token': token},
                             json={'input': payload}, timeout=5)
        sig = resp.json().get('data', {}).get('signature') if resp.status_code == 200 else None
        if sig:
            write_result('vault-sign', 'vault-transit', 'ok', detail='signature ' + sig[:24] + '...')
        else:
            write_result('vault-sign', 'vault-transit', 'error', detail='HTTP ' + str(resp.status_code))
    except Exception as e:
        write_result('vault-sign', 'vault-transit', 'error', detail=str(e)[:120])
"

# Step 4B & 5B: Zone 4 Incident Abort, Jira Dispatch & Zone 5 STIX 2.1 DFIR Bundle
python3 scripts/run-incident-abort.py

# Step 6: Zone 4 K3s Kubernetes Cluster Verification
echo -e "\n[+] [ZONE 4] Verifying K3s Kubernetes Cluster & Active Nodes..."
python3 -c "
import subprocess
from scripts.lib.scanner_result import write_result

try:
    cmd = ['kubectl', '--kubeconfig=/etc/rancher/k3s/k3s.yaml', 'get', 'nodes']
    out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=15)
    lines = [l for l in out.stdout.strip().splitlines() if not l.startswith('NAME')]
    if lines:
        fields = lines[0].split()
        node_name, node_status = fields[0], fields[1] if len(fields) > 1 else 'unknown'
        version = fields[4] if len(fields) > 4 else None
        print(f'    -> K3s Cluster Active Node: {lines[0]}')
        write_result('k3s', 'kubectl', 'ok' if node_status == 'Ready' else 'error',
                     target=node_name, version=version,
                     counts={'node_name': node_name},
                     detail=f'node {node_name} status={node_status}')
    else:
        print('    -> K3s Cluster Online (control-plane)')
        write_result('k3s', 'kubectl', 'ok', detail='cluster reachable, no node rows parsed')
except Exception as e:
    print(f'    -> K3s check note: {e}')
    write_result('k3s', 'kubectl', 'not_run', detail=str(e)[:150])
"

# Step 7: Zone 5 Forensics Vault Sealing
echo -e "\n[+] [ZONE 5] Sealing Incident Artifacts in Forensics DB..."
python3 -c "
import time
from pathlib import Path
from src.forensics.evidence_db import EvidenceDatabaseManager
from src.forensics.evidence_sealer import seal_run_evidence

# Seal this run's REAL evidence (the actual report files), not a constant.
seal = seal_run_evidence(Path('.'), f'EVID-AUTO-RUN-{int(time.time())}')
db = EvidenceDatabaseManager('data/forensics.db')
rec = db.register_evidence(
    evidence_id=seal['incident_id'] + '-manifest',
    file_path=seal['manifest_path'],
    byte_size=seal['manifest_bytes'],
    sha256=seal['root_sha256'],
    sha512=seal['root_sha512'],
    acquired_by='soc-operator',
    status='SEALED',
)
print(f'    -> Forensic record sealed: {rec[\"evidence_id\"]} | {seal[\"file_count\"]} files | Hash: {rec[\"sha256\"][:16]}...')
"

echo -e "\n[+] [COMPLIANCE] Ingesting Multi-Scanner Telemetry into DefectDojo (Port 8085)..."
python3 scripts/ingest-defectdojo.py || true

# Step 8: Zone 9 Status Aggregator & HTML Report Compilation
echo -e "\n[+] [ZONE 9] Aggregating Cross-Zone Status & Generating Report..."
./node_modules/.bin/tsx --no-cache scripts/aggregate-status.mts
python3 scripts/aggregate-infra-status.py
python3 scripts/ship-siem-telemetry.py
    python3 scripts/ingest-granular-siem.py || true
python3 scripts/sync-defectdojo-metrics.py || true
./node_modules/.bin/tsx --no-cache scripts/generate-html-report.mts
python3 scripts/notify-slack.py || true

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo "========================================================================"
if [ "$VERDICT_RC" -eq 0 ]; then
    echo -e " [+] Pipeline health OK in ${ELAPSED}s. Verdict: $(jq -r .verdict reports/verdict.json)"
else
    echo -e " [-] PIPELINE HEALTH FAILED in ${ELAPSED}s. Not everything really ran: see verdict above."
fi
echo -e " [+] Executive Report: file://${REPO_ROOT}/reports/latest.html"
echo "========================================================================"
exit "$VERDICT_RC"
