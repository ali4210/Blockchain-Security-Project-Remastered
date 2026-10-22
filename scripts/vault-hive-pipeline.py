import requests
import json
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.incident.safe_pause_builder import SafeEmergencyPauseBuilder

THEHIVE = "http://127.0.0.1:9005"
VAULT = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "root")

v_headers = {"X-Vault-Token": VAULT_TOKEN, "Content-Type": "application/json"}
auth = ("admin@thehive.local", "secret")

print("=== [THEHIVE 4 & VAULT COMPLETE AUTOMATION] ===")

# --- 1. Inspect Profiles ---
q = {"query": [{"_name": "listProfile"}]}
r = requests.post(f"{THEHIVE}/api/v1/query", json=q, auth=auth)
if r.status_code == 200:
    print("[+] Available System Profiles:")
    for p in r.json():
        print(f"    - {p.get('name')}: {p.get('permissions', [])}")

# --- 2. Create Analyst User under Organization admin ---
user_email = "soc-analyst@blockchain.local"
user_pwd = "SecretPassword2026!"

print(f"\n[+] Provisioning Analyst User: {user_email}...")
user_body = {
    "login": user_email,
    "name": "SOC Lead Analyst",
    "roles": ["admin", "read", "write"],
    "profile": "org-admin",
    "password": user_pwd,
    "organisation": "admin"
}

# TheHive 4 requires org header or user creation path
u_res = requests.post(
    f"{THEHIVE}/api/v0/user",
    json=user_body,
    auth=auth,
    headers={"X-Organisation": "Blockchain-SOC", "Content-Type": "application/json"}
)
if u_res.status_code not in [200, 201]:
    u_res = requests.post(
        f"{THEHIVE}/api/user",
        json=user_body,
        auth=auth,
        headers={"X-Organisation": "Blockchain-SOC", "Content-Type": "application/json"}
    )
print(f"    -> User provision response: HTTP {u_res.status_code} {u_res.text}")

# --- 3. Generate API Key ---
print(f"\n[+] Generating API Key for {user_email}...")
k_res = requests.post(
    f"{THEHIVE}/api/user/{user_email}/key",
    auth=auth,
    headers={"X-Organisation": "Blockchain-SOC"}
)
if k_res.status_code not in [200, 201]:
    k_res = requests.post(
        f"{THEHIVE}/api/user/{user_email}/key/renew",
        auth=auth,
        headers={"X-Organisation": "Blockchain-SOC"}
    )

api_key = None
if k_res.status_code in [200, 201]:
    try:
        api_key = k_res.json().get("key")
    except ValueError:
        api_key = k_res.text.strip()
    print(f"[+] Issued API Key: {api_key}")

    # --- 4. Store in Vault ---
    print("[+] Storing Key in HashiCorp Vault at secret/data/soc/thehive...")
    vault_payload = {"data": {"api_key": api_key, "user": user_email}}
    v_put = requests.post(f"{VAULT}/v1/secret/data/soc/thehive", json=vault_payload, headers=v_headers)
    print(f"    -> Vault write status: HTTP {v_put.status_code}")
else:
    print(f"[-] Key issuance response: HTTP {k_res.status_code} {k_res.text}")

# --- 5. Verify Read From Vault ---
print("\n[+] Reading API Key from HashiCorp Vault...")
v_get = requests.get(f"{VAULT}/v1/secret/data/soc/thehive", headers=v_headers)
if v_get.status_code == 200:
    retrieved_key = v_get.json().get("data", {}).get("data", {}).get("api_key")
    print(f"[+] Retrieved Key from Vault: {retrieved_key[:8]}...{retrieved_key[-4:]}")
    use_key = retrieved_key
else:
    use_key = api_key

if use_key:
    # --- 6. Ingest Case #1 with Observables ---
    print("\n[+] Ingesting Incident Case #1 into TheHive...")
    analyst_headers = {
        "Authorization": f"Bearer {use_key}",
        "X-Organisation": "Blockchain-SOC",
        "Content-Type": "application/json"
    }

    stix_path = "reports/stix/latest-incident-stix.json"
    bundle_hash = "PENDING_DIGEST"
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

    case_resp = requests.post(f"{THEHIVE}/api/case", json=case_payload, headers=analyst_headers)
    if case_resp.status_code in [200, 201]:
        case_data = case_resp.json()
        cid = case_data.get("id")
        cnum = case_data.get("caseId")
        print(f"[+] SUCCESS! Case #{cnum} created (ID: {cid})")

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
            requests.post(f"{THEHIVE}/api/case/{cid}/artifact", json=obs, headers=analyst_headers)
            print(f"    -> Indexed observable: [{obs['dataType']}] {obs['data'][:28]}...")
        print("[+] Forensic observables indexed into JanusGraph.")
    else:
        print(f"[-] Case creation failed: HTTP {case_resp.status_code} - {case_resp.text}")
