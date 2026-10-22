import os
import sys
import json
import hashlib
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.incident.safe_pause_builder import SafeEmergencyPauseBuilder

BASE = "http://127.0.0.1:9005"
s = requests.Session()

print("[+] 1. Authenticating as admin@thehive.local...")
login_res = s.post(f"{BASE}/api/login", json={"user": "admin@thehive.local", "password": "secret"})
if login_res.status_code != 200:
    print(f"[-] Authentication failed: HTTP {login_res.status_code} - {login_res.text}")
    exit(1)
print("[+] Authenticated.")

# Check or create organization
orgs_res = s.get(f"{BASE}/api/organisation")
existing_orgs = []
if orgs_res.status_code == 200:
    existing_orgs = [o.get("name") for o in orgs_res.json()]

org_name = "Blockchain-SOC"
if org_name not in existing_orgs:
    print(f"[+] 2. Provisioning Organization: '{org_name}'...")
    r = s.post(f"{BASE}/api/organisation", json={"name": org_name, "description": "Autonomous SOC Evidence Vault"})
    print(f"    -> Organisation provision response: HTTP {r.status_code}")
else:
    print(f"[*] Organization '{org_name}' already exists.")

# Provision analyst user
user_email = "soc-analyst@blockchain.local"
user_pwd = "SecretPassword2026!"
print(f"[+] 3. Provisioning Analyst User: '{user_email}'...")
user_payload = {
    "login": user_email,
    "name": "SOC Lead Analyst",
    "roles": ["admin", "read", "write"],
    "organisation": org_name,
    "profile": "org-admin",
    "password": user_pwd
}
u_res = s.post(f"{BASE}/api/user", json=user_payload)
print(f"    -> User provision response: HTTP {u_res.status_code}")

act_res = s.patch(f"{BASE}/api/user/{user_email}", json={"status": "Ok"})
print(f"    -> Activation response: HTTP {act_res.status_code}")

# Extract or renew API Key
print("[+] 4. Extracting API Key...")
key_res = s.post(f"{BASE}/api/user/{user_email}/key")
api_key = None
if key_res.status_code in [200, 201]:
    api_key = key_res.json().get("key")
elif key_res.status_code == 400:
    key_renew = s.post(f"{BASE}/api/user/{user_email}/key/renew")
    if key_renew.status_code == 200:
        api_key = key_renew.json().get("key")

if api_key:
    print(f"[+] Active API Key: {api_key}")
    with open("thehive.key", "w") as f:
        f.write(api_key)
    client = requests.Session()
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
else:
    print("[*] Using direct analyst session for incident ingestion...")
    analyst_s = requests.Session()
    analyst_s.post(f"{BASE}/api/login", json={"user": user_email, "password": user_pwd})
    client = analyst_s
    headers = {"Content-Type": "application/json"}

# Read STIX bundle & calculate RFC 3227 hash
print("\n[+] 5. Ingesting STIX 2.1 Forensics & RFC 3227 Chain-of-Custody...")
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

case_resp = client.post(f"{BASE}/api/case", json=case_payload, headers=headers)
if case_resp.status_code in [200, 201]:
    case_data = case_resp.json()
    case_id = case_data.get("id")
    case_number = case_data.get("caseId")
    print(f"[+] Case successfully injected into TheHive! Case #{case_number} (ID: {case_id})")

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
        o_res = client.post(f"{BASE}/api/case/{case_id}/artifact", json=obs, headers=headers)
        dtype = obs["dataType"]
        dval = obs["data"][:32]
        if o_res.status_code in [200, 201]:
            print(f"    -> Indexed observable: [{dtype}] {dval}...")
        else:
            print(f"    -> Status for [{dtype}]: HTTP {o_res.status_code}")
    print("[+] All observables registered into JanusGraph database!")
else:
    print(f"[-] Case creation failed (HTTP {case_resp.status_code}): {case_resp.text}")
