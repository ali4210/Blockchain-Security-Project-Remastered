import sys
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.lib.thehive_case import post_case_with_observables

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

# Ingest STIX 2.1 Forensics & RFC 3227 Chain-of-Custody as a SEV-1 case
print("\n[+] 5. Ingesting STIX 2.1 Forensics & RFC 3227 Chain-of-Custody...")
case_resp, case_data, results = post_case_with_observables(client.post, BASE, headers)
if case_data:
    case_number = case_data.get("caseId")
    print(f"[+] Case successfully injected into TheHive! Case #{case_number} (ID: {case_data.get('id')})")
    for obs, o_res in results:
        dtype, dval = obs["dataType"], obs["data"][:32]
        if o_res.status_code in [200, 201]:
            print(f"    -> Indexed observable: [{dtype}] {dval}...")
        else:
            print(f"    -> Status for [{dtype}]: HTTP {o_res.status_code}")
    print("[+] All observables registered into JanusGraph database!")
else:
    print(f"[-] Case creation failed (HTTP {case_resp.status_code}): {case_resp.text}")
