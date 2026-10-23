#!/usr/bin/env python3
"""One-time provisioning: writes the real Jira credentials already in `.env`
into Vault at secret/data/soc/jira, so jira_dispatcher.py can read them the
same way every other integration (Slack, TheHive, DefectDojo) reads its
credentials -- Vault first -- instead of relying on `.env` being manually
sourced, which the real pipeline entrypoint (`make pipeline-all`) never does.
"""
import os
import sys
import requests

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")


def _load_dotenv(path=".env"):
    env = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k] = v.strip().strip('"').strip("'")
    return env


def main():
    if not VAULT_TOKEN:
        print("[-] VAULT_TOKEN not set in environment; aborting.")
        sys.exit(1)

    env = _load_dotenv()
    url = env.get("JIRA_URL")
    user = env.get("JIRA_USER")
    token = env.get("JIRA_TOKEN")
    project_key = env.get("JIRA_PROJECT_KEY", "KAN")
    if not (url and user and token):
        print("[-] JIRA_URL/JIRA_USER/JIRA_TOKEN not all found in .env; aborting.")
        sys.exit(1)

    headers = {"X-Vault-Token": VAULT_TOKEN}
    payload = {"data": {"url": url, "user": user, "token": token, "project_key": project_key}}
    resp = requests.post(f"{VAULT_ADDR}/v1/secret/data/soc/jira", json=payload, headers=headers, timeout=5)
    print(f"[+] Vault write response: HTTP {resp.status_code}")
    if resp.status_code not in (200, 204):
        print(f"    {resp.text}")
        sys.exit(1)

    verify = requests.get(f"{VAULT_ADDR}/v1/secret/data/soc/jira", headers=headers, timeout=5)
    if verify.status_code != 200:
        print(f"[-] Verify read failed: HTTP {verify.status_code}")
        sys.exit(1)

    stored = verify.json().get("data", {}).get("data", {})
    tok = stored.get("token") or ""
    masked = f"{tok[:8]}...{tok[-4:]}" if len(tok) > 12 else "***"
    print(f"[+] Verified read-back from Vault: url={stored.get('url')} user={stored.get('user')} "
          f"project_key={stored.get('project_key')} token={masked}")


if __name__ == "__main__":
    main()
