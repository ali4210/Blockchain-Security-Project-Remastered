import os
import json
import requests
from pathlib import Path
from typing import Dict, Any

def load_env_file():
    env_path = Path(".env")
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip().strip('"').strip("'")

load_env_file()

class JiraIncidentDispatcher:
    """Dispatches automated SEV-1 emergency response tickets to Jira upon critical exploit confirmation."""

    def __init__(self, jira_url: str = None, username: str = None, api_token: str = None, project_key: str = None):
        self.jira_url = jira_url or os.getenv("JIRA_URL", "https://saleemalimohammad211126.atlassian.net")
        self.username = username or os.getenv("JIRA_USER", "")
        self.api_token = api_token or os.getenv("JIRA_TOKEN", "")
        self.project_key = project_key or os.getenv("JIRA_PROJECT_KEY", "KAN")

    def dispatch_sev1_ticket(
        self,
        incident_id: str,
        contract: str,
        vulnerability: str,
        dread_score: float,
        safe_tx_hash: str,
        stix_bundle_path: str
    ) -> Dict[str, Any]:
        summary = f"[SEV-1 ALERT] Autonomous SOC: Exploit Confirmed on {contract}"
        description = (
            f"Incident Telemetry: {incident_id}\n\n"
            f"Target Contract: {contract}\n"
            f"Identified Flaw: {vulnerability} (OWASP SC01)\n"
            f"DREAD Risk Score: {dread_score} / 10.0 (CRITICAL)\n"
            f"Safe Emergency Pause Tx: {safe_tx_hash}\n"
            f"STIX 2.1 Threat Indicator: {stix_bundle_path}\n\n"
            f"Automated Containment Actions Executed:\n"
            f"1. Ingress NetworkPolicy applied in K3s namespace 'blockchain-soc'\n"
            f"2. Forensics evidence cryptographically sealed in DFIR DB\n"
            f"3. Production readiness deployment gate set to FAIL-CLOSED"
        )

        ticket_payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": "Task"}
            }
        }

        # If live credentials exist, dispatch via Jira Cloud REST API v2
        if self.api_token and "your_" not in self.api_token and self.username:
            try:
                endpoint = f"{self.jira_url.rstrip('/')}/rest/api/2/issue"
                resp = requests.post(
                    endpoint,
                    json=ticket_payload,
                    auth=(self.username, self.api_token),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    timeout=5
                )
                if resp.status_code in [200, 201]:
                    issue_key = resp.json().get("key", f"{self.project_key}-AUTO")
            try:
                os.makedirs("reports", exist_ok=True)
                with open("reports/latest-jira-ticket.txt", "w", encoding="utf-8") as jtf:
                    jtf.write(issue_key.strip())
            except Exception as e:
                pass
                    return {
                        "status": "dispatched",
                        "key": issue_key,
                        "url": f"{self.jira_url.rstrip('/')}/browse/{issue_key}"
                    }
                else:
                    print(f"[-] Jira API rejected ({resp.status_code}): {resp.text}")
            except Exception as e:
                print(f"[-] Jira API connection warning: {e}")

        # Local fallback artifact
        local_key = f"{self.project_key}-{incident_id[-4:]}"
        ticket_file = f"reports/jira-{local_key}.json"
        Path("reports").mkdir(exist_ok=True)
        with open(ticket_file, "w", encoding="utf-8") as tf:
            json.dump({"key": local_key, "fields": ticket_payload["fields"]}, tf, indent=2)

        return {"status": "recorded_local", "key": local_key, "artifact": ticket_file}

if __name__ == "__main__":
    dispatcher = JiraIncidentDispatcher()
    res = dispatcher.dispatch_sev1_ticket(
        incident_id="INC-LIVE-001",
        contract="VulnerableVault",
        vulnerability="ReentrancyExternalCall",
        dread_score=8.5,
        safe_tx_hash="0x78a1bcde...",
        stix_bundle_path="reports/stix/latest-incident-stix.json"
    )
    print(f"[+] Jira Dispatch Result: Status={res['status']} Key={res.get('key')} URL={res.get('url')}")
