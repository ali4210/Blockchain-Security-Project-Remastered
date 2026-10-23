import requests
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.lib.thehive_case import post_case_with_observables

THEHIVE = "http://127.0.0.1:9005"
VAULT = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "root")

v_headers = {"X-Vault-Token": VAULT_TOKEN, "Content-Type": "application/json"}
auth = ("admin@thehive.local", "secret")
org_headers = {"X-Organisation": "Blockchain-SOC", "Content-Type": "application/json"}

print("=== [THEHIVE 4 & VAULT INTEGRATION] ===")

# 1. Query existing users in TheHive
user_email = "soc-analyst@blockchain.local"
user_pwd = "SecretPassword2026!"

print(f"[+] 1. Checking if {user_email} already exists...")
r = requests.get(f"{THEHIVE}/api/user/{user_email}", auth=auth, headers=org_headers)

if r.status_code == 404:
    print(f"[*] Provisioning {user_email} under 'admin' organisation...")
    # TheHive 4 multi-tenancy schema:
    payload = {
        "login": user_email,
        "name": "SOC Lead Analyst",
        "profile": "org-admin",
        "password": user_pwd,
        "organisation": "admin",
        "organisations": [
            {
                "organisation": "admin",
                "profile": "org-admin"
            }
        ]
    }
    create_res = requests.post(f"{THEHIVE}/api/v1/user", json=payload, auth=auth, headers=org_headers)
    if create_res.status_code not in [200, 201]:
        # Fallback to /api/user with organisation mapping
        create_res = requests.post(f"{THEHIVE}/api/user", json=payload, auth=auth, headers=org_headers)
    print(f"    -> Provision response: HTTP {create_res.status_code} {create_res.text}")
else:
    print(f"[+] User {user_email} exists (HTTP {r.status_code}).")

# 2. Extract or Renew API Key
print(f"[+] 2. Generating API Key for {user_email}...")
key_res = requests.post(f"{THEHIVE}/api/v1/user/{user_email}/key", auth=auth, headers=org_headers)
if key_res.status_code not in [200, 201]:
    key_res = requests.post(f"{THEHIVE}/api/v1/user/{user_email}/key/renew", auth=auth, headers=org_headers)
if key_res.status_code not in [200, 201]:
    key_res = requests.post(f"{THEHIVE}/api/user/{user_email}/key", auth=auth, headers=org_headers)

api_key = None
if key_res.status_code in [200, 201]:
    try:
        api_key = key_res.json().get("key")
    except ValueError:
        api_key = key_res.text.strip()
    print(f"[+] TheHive API Key: {api_key}")

    # 3. Store API Key in HashiCorp Vault
    print(f"[+] 3. Storing API Key in HashiCorp Vault (secret/data/soc/thehive)...")
    vault_payload = {"data": {"api_key": api_key, "user": user_email}}
    v_put = requests.post(f"{VAULT}/v1/secret/data/soc/thehive", json=vault_payload, headers=v_headers)
    print(f"    -> Vault write response: HTTP {v_put.status_code}")
else:
    print(f"[-] Key generation returned: HTTP {key_res.status_code} - {key_res.text}")

# 4. Fetch Key Back from HashiCorp Vault
print("\n[+] 4. Verifying read from HashiCorp Vault...")
v_get = requests.get(f"{VAULT}/v1/secret/data/soc/thehive", headers=v_headers)
if v_get.status_code == 200:
    retrieved_key = v_get.json().get("data", {}).get("data", {}).get("api_key")
    print(f"[+] Successfully retrieved API key from Vault: {retrieved_key[:8]}...{retrieved_key[-4:]}")

    # 5. Ingest Zone 5 STIX 2.1 Forensics Bundle as Case #1
    print("\n[+] 5. Ingesting STIX 2.1 Evidence & RFC 3227 Chain-of-Custody...")
    analyst_headers = {
        "Authorization": f"Bearer {retrieved_key}",
        "X-Organisation": "Blockchain-SOC",
        "Content-Type": "application/json"
    }

    c_res, case_data, results = post_case_with_observables(requests.post, THEHIVE, analyst_headers)
    if case_data:
        cnum = case_data.get("caseId")
        print(f"[+] Case #{cnum} created in TheHive! (ID: {case_data.get('id')})")
        for obs, _o_res in results:
            print(f"    -> Indexed: [{obs['dataType']}] {obs['data'][:28]}...")
        print("[+] Forensic evidence sealed into JanusGraph.")
    else:
        print(f"[-] Case creation status: HTTP {c_res.status_code} - {c_res.text}")
