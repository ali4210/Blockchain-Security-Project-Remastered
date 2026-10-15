import os
import json
import requests
from pathlib import Path
from datetime import datetime, timezone

class JiraIncidentDispatcher:
    """Dispatches automated SEV-1 emergency response tickets to Jira upon critical exploit detection."""

    def __init__(self, jira_url: str = None, username: str = None, api_token: str = None, project_key: str = None):
        self.jira_url = jira_url or os.getenv("JIRA_INSTANCE_URL", "https://saleemalimohammad211126.atlassian.net")
        self.username = username or os.getenv("JIRA_USER_EMAIL", "saleemali.mohammad@gmail.com")
        self.api_token = api_token or os.getenv("JIRA_API_TOKEN", "")
        self.project_key = project_key or os.getenv("JIRA_PROJECT_KEY", "KAN")

    def dispatch_sev1_ticket(
        self,
        incident_id: str,
        contract_name: str,
        dread_score: float,
        findings_summary: str,
        safe_pause_payload: str = None,
        avs_quorum: bool = True
    ) -> dict:
        summary = f"[SEV-1 AUTO-HALT] Exploitation Prevented on {contract_name} (DREAD {dread_score})"
        desc = (
            f"*Autonomous Blockchain SOC — Emergency Halt Consensus Event*\n\n"
            f"*Incident ID:* `{incident_id}`\n"
            f"*Target Contract:* `{contract_name}`\n"
            f"*Assessed DREAD Score:* `{dread_score} / 10.0`\n"
            f"*AVS Byzantine Consensus:* `{'VERIFIED (100% agreement)' if avs_quorum else 'PENDING'}`\n\n"
            f"h3. Technical Triage & Findings\n{findings_summary}\n\n"
            f"h3. Recommended Immediate Mitigation Actions\n"
            f"- Gnosis Safe emergency pause proposed: `{safe_pause_payload or 'N/A'}`\n"
            f"- Autonomous execution halted deployment at Zone 9 deny-by-default readiness gate.\n"
            f"- Forensic volatile memory state bundle sealed with Merkle verification.\n"
        )

        ticket_payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary,
                "description": desc,
                "issuetype": {"name": "Task"}
            }
        }

        # If live credentials exist, dispatch via Jira Cloud REST API v2
        if self.jira_url and self.username and self.api_token:
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
                    except Exception:
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
        try:
            with open(ticket_file, "w", encoding="utf-8") as tf:
                json.dump({"key": local_key, "fields": ticket_payload["fields"]}, tf, indent=2)
            with open("reports/latest-jira-ticket.txt", "w", encoding="utf-8") as jtf:
                jtf.write(local_key.strip())
        except Exception:
            pass
        return {"status": "recorded_local", "key": local_key, "artifact": ticket_file}

if __name__ == "__main__":
    dispatcher = JiraIncidentDispatcher()
    res = dispatcher.dispatch_sev1_ticket(
        incident_id="INC-TEST-001",
        contract_name="VulnerableVault.sol",
        dread_score=8.4,
        findings_summary="Reentrancy exploit path verified via Slither AST and Mythril symbolic solver.",
        safe_pause_payload="0x8456cb59",
        avs_quorum=True
    )
    print(f"[+] Jira Dispatch Result: Status={res['status']} Key={res.get('key')} URL={res.get('url')}")
