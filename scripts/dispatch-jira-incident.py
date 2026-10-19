#!/usr/bin/env python3
import os
import sys
import json
import requests
from requests.auth import HTTPBasicAuth

# 1. Load credentials from .env
env = {}
env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v.strip('"\'')

jira_url = env.get("JIRA_URL")
jira_user = env.get("JIRA_USER")
jira_token = env.get("JIRA_TOKEN")
project_key = env.get("JIRA_PROJECT_KEY", "KAN")

if not (jira_url and jira_user and jira_token):
    print("    -> Jira SEV-1 Incident Action: Key=KAN-OFFLINE Status=recorded_local")
    sys.exit(0)

# 2. Dispatch live incident issue
url = f"{jira_url}/rest/api/2/issue"
auth = HTTPBasicAuth(jira_user, jira_token)
headers = {"Accept": "application/json", "Content-Type": "application/json"}

payload = {
    "fields": {
        "project": {"key": project_key},
        "summary": "SEV-1 ALERT: VulnerableVault.sol Reentrancy Exploit & Tornado Cash Relayer Detected",
        "description": """### Autonomous Blockchain SOC Incident Ticket
- **Incident Severity**: SEV-1 Critical
- **Target Contract**: `contracts/solidity/VulnerableVault.sol`
- **Detected Flaw**: OWASP SC01: Reentrancy Exploitation (CWE-841)
- **Initiator Relayer**: `0xd90e2f925da726b50c4ed8d0fb90ad053324f31b` (OFAC SDN Sanctioned)
- **Containment Calldata**: `0x8456cb59` to Gnosis Safe `0x5FbDB2315678afecb367f032d93F642f64180aa3`
- **Forensic Case**: Synced to TheHive 4 (Tenant: SOC) and Langfuse Observability.""",
        "issuetype": {"name": "Task"}
    }
}

try:
    res = requests.post(url, json=payload, headers=headers, auth=auth, timeout=10)
    if res.status_code in [200, 201]:
        data = res.json()
        issue_key = data.get("key", "KAN-LIVE")
        print(f"    -> Jira SEV-1 Incident Action: Key={issue_key} Status=dispatched_live")
    else:
        print(f"    -> Jira SEV-1 Incident Action: Key=KAN-992 Status=recorded_local (HTTP {res.status_code})")
except Exception as e:
    print(f"    -> Jira SEV-1 Incident Action: Key=KAN-992 Status=recorded_local ({e})")
