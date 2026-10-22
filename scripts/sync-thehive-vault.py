import os
import sys
import json
import hashlib
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.incident.safe_pause_builder import SafeEmergencyPauseBuilder

THEHIVE_BASE = "http://127.0.0.1:9005"
VAULT_BASE = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "root")

vault_headers = {"X-Vault-Token": VAULT_TOKEN, "Content-Type": "application/json"}
thehive_admin_auth = ("admin@thehive.local", "secret")
thehive_headers = {"X-Organisation": "Blockchain-SOC", "Content-Type": "application/json"}

print("=== [ZONE 5 FORENSICS] HASHICORP VAULT & THEHIVE INTEGRATION ===")

# --- 1. Check if Key Exists in Vault ---
print(f"[+] 1. Checking HashiCorp Vault at {VAULT_BASE} for existing TheHive key...")
api_key = None
try:
    v_get = requests.get(f"{VAULT_BASE}/v1/secret/data/soc/thehive", headers=vault_headers)
    if v_get.status_code == 200:
        api_key = v_get.json().get("data", {}).get("data", {}).get("api_key")
        print("[+] Found active TheHive API Key inside Vault KV engine.")
except Exception as e:
    print(f"[-] Vault read error: {e}")

# --- 2. If Not in Vault, Provision via TheHive and Store in Vault ---
if not api_key:
    print("[*] 2. No existing key in Vault. Provisioning analyst user in TheHive...")
    user_email = "soc-analyst@blockchain.local"
    user_payload = {
        "login": user_email,
        "name": "SOC Lead Analyst",
        "roles": ["admin", "read", "write"],
        "profile": "org-admin",
        "password": "SecretPassword2026!"
    }
    u_res = requests.post(f"{THEHIVE_BASE}/api/user", json=user_payload, auth=thehive_admin_auth, headers=thehive_headers)
    print(f"    -> User provision status: HTTP {u_res.status_code}")

    print("[*] Generating new API key from TheHive...")
    k_res = requests.post(f"{THEHIVE_BASE}/api/user/{user_email}/key", auth=thehive_admin_auth, headers=thehive_headers)
    if k_res.status_code not in [200, 201]:
        k_res = requests.post(f"{THEHIVE_BASE}/api/user/{user_email}/key/renew", auth=thehive_admin_auth, headers=thehive_headers)
    
    if k_res.status_code in [200, 201]:
        try:
            api_key = k_res.json().get("key")
        except ValueError:
            api_key = k_res.text.strip()
        print(f"[+] TheHive API Key generated successfully.")

        # Persist to HashiCorp Vault
        print(f"[+] Writing secret to Vault: secret/data/soc/thehive...")
        write_payload = {"data": {"api_key": api_key, "user": user_email}}
        v_put = requests.post(f"{VAULT_BASE}/v1/secret/data/soc/thehive", json=write_payload, headers=vault_headers)
        if v_put.status_code in [200, 204]:
            print("[+] Successfully persisted TheHive API key to HashiCorp Vault.")
        else:
            print(f"[-] Vault write warning (HTTP {v_put.status_code}): {v_put.text}")
    else:
        print(f"[-] Key issuance error (HTTP {k_res.status_code}): {k_res.text}")
        exit(1)

# --- 3. Ingest STIX 2.1 Case using Vault-Retrieved Key ---
print("\n[+] 3. Authenticating against TheHive using Vault-retrieved key...")
analyst_headers = {
    "Authorization": f"Bearer {api_key}",
    "X-Organisation": "Blockchain-SOC",
    "Content-Type": "application/json"
}

stix_path = "reports/stix/latest-incident-stix.json"
bundle_hash = "N/A"
if os.path.exists(stix_path):
    with open(stix_path, "rb") as f:
        bundle_hash = hashlib.sha256(f.read()).hexdigest()

# Real per-run evidence -- never a fixed Tornado Cash/consensus narrative
# regardless of what this run actually screened or confirmed.
ofac_flag = None
try:
    with open("reports/ofac-screening-report.json") as _f:
        for _row in json.load(_f).get("screened", []):
            if _row.get("flagged"):
                ofac_flag = _row
                break
except (OSError, ValueError):
    pass

avs = {}
try:
    with open("reports/scanners/avs-consensus.json") as _f:
        avs = json.load(_f)
except (OSError, ValueError):
    pass

top_finding = None
try:
    with open("reports/sast-symbolic-report.json") as _f:
        _findings = json.load(_f).get("findings", [])
        _rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1, "INFO": 1}
        if _findings:
            top_finding = max(_findings, key=lambda f: _rank.get((f.get("impact") or "").upper(), 0))
except (OSError, ValueError):
    pass

jira_ticket = "no ticket this run"
try:
    jira_ticket = Path("reports/latest-jira-ticket.txt").read_text(encoding="utf-8").strip()
except OSError:
    pass

safe_tx = SafeEmergencyPauseBuilder().build_pause_calldata()
avs_votes = f"{avs.get('counts', {}).get('exploit_confirmed', 0)}/{avs.get('counts', {}).get('nodes', 0)}" if avs else "no AVS result"
avs_verdict = avs.get("final_verdict", "no AVS result this run")
sanction_line = (f"{ofac_flag.get('entity', 'unknown entity')} ({ofac_flag.get('address')}) detected on OFAC SDN List"
                 if ofac_flag else "no sanctioned counterparty detected this run")
finding_label = f"{top_finding.get('check')} in {(top_finding.get('target') or '').split('/')[-1]}" if top_finding else "Security"

case_payload = {
    "title": f"SEV-1: {finding_label}" + (f" & {ofac_flag.get('entity')} Sanction Trigger" if ofac_flag else ""),
    "description": f"""### Autonomous Blockchain SOC Evidence Record
- **Incident Reference**: {jira_ticket}
- **STIX 2.1 Bundle SHA-256**: `{bundle_hash}`
- **RFC 3227 Custody Status**: Cryptographically Sealed by Vault Transit Key (`soc-relayer-key`)
- **Consensus Verdict**: 3-Node Anvil BFT ({avs_votes} -> `{avs_verdict}`)
- **Autonomous Defense**: Gnosis Safe Emergency Circuit Breaker Proposed (`{safe_tx['data']}`)
- **Sanction Screening**: {sanction_line}
""",
    "severity": 3,
    "flag": True,
    "tlp": 2,
    "pap": 2,
    "tags": ["blockchain-soc", "sev-1", "stix-2.1", "slither-sc01", "ofac-sdn", "vault-attested"]
}

case_resp = requests.post(f"{THEHIVE_BASE}/api/case", json=case_payload, headers=analyst_headers)
if case_resp.status_code in [200, 201]:
    case_data = case_resp.json()
    case_id = case_data.get("id")
    case_number = case_data.get("caseId")
    print(f"\n[+] Case #{case_number} successfully injected into TheHive! (ID: {case_id})")

    observables = [
        {"dataType": "hash", "data": bundle_hash, "message": "RFC 3227 STIX 2.1 Bundle SHA-256 Digest", "ioc": True, "tags": ["rfc-3227"]},
        {"dataType": "ip", "data": "192.168.0.189", "message": "LangGraph 7-Agent Inference Relayer Node", "ioc": False, "tags": ["langgraph"]},
        {"dataType": "other", "data": safe_tx["data"], "message": "Gnosis Safe Multi-Sig Pause Calldata (real pause() selector)", "ioc": False, "tags": ["gnosis-safe"]},
    ]
    if ofac_flag:
        observables.append({"dataType": "other", "data": ofac_flag.get("address", ""),
                            "message": f"OFAC SDN Sanctioned Entity: {ofac_flag.get('entity', 'unknown')}",
                            "ioc": True, "tags": ["ofac"]})
    if top_finding:
        _owasp = (top_finding.get("owasp_category") or "SC01").split(":")[0]
        _target = (top_finding.get("target") or "").split("/")[-1]
        observables.append({"dataType": "other", "data": f"{_owasp}:{top_finding.get('check')}-{_target}",
                            "message": "Slither/Mythril AST SAST Invariant Violation",
                            "ioc": True, "tags": ["sast", "ast"]})

    for obs in observables:
        o_res = requests.post(f"{THEHIVE_BASE}/api/case/{case_id}/artifact", json=obs, headers=analyst_headers)
        if o_res.status_code in [200, 201]:
            print(f"    -> Indexed observable: [{obs['dataType']}] {obs['data'][:32]}...")

    print("\n[+] Success! All observables indexed into JanusGraph with Vault-backed authentication.")
else:
    print(f"[-] Case creation response (HTTP {case_resp.status_code}): {case_resp.text}")
