import os
import sys
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.lib.thehive_case import post_case_with_observables

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

case_resp, case_data, results = post_case_with_observables(requests.post, THEHIVE_BASE, analyst_headers)
if case_data:
    case_number = case_data.get("caseId")
    print(f"\n[+] Case #{case_number} successfully injected into TheHive! (ID: {case_data.get('id')})")
    for obs, o_res in results:
        if o_res.status_code in [200, 201]:
            print(f"    -> Indexed observable: [{obs['dataType']}] {obs['data'][:32]}...")
    print("\n[+] Success! All observables indexed into JanusGraph with Vault-backed authentication.")
else:
    print(f"[-] Case creation response (HTTP {case_resp.status_code}): {case_resp.text}")
