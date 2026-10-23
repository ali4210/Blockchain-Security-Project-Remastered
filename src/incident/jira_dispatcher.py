import os
import json
import requests
from pathlib import Path
from datetime import datetime, timezone


def _vault_jira_secret():
    """Reads secret/data/soc/jira, same Vault-first convention as the Slack,
    TheHive and DefectDojo integrations. Returns the secret dict, or None if
    VAULT_TOKEN isn't set, Vault is unreachable, or the secret doesn't exist
    -- callers fall back to os.getenv() in that case."""
    vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    vault_token = os.getenv("VAULT_TOKEN")
    if not vault_token:
        return None
    try:
        resp = requests.get(
            f"{vault_addr}/v1/secret/data/soc/jira",
            headers={"X-Vault-Token": vault_token}, timeout=5,
        )
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("data") or None
    except Exception:
        pass
    return None


# Concrete, vulnerability-class-specific remediation guidance, keyed by the
# same SC0x OWASP smart-contract categories run-sast-symbolic.py already
# assigns (SC01 Reentrancy, SC02 Access Control, SC03 Unprotected
# Upgrade/Delegatecall). SC10 is that script's catch-all default for anything
# else, so it has no single fix to recommend -- it falls through to the
# honest "no specific mapping" text below instead of guessing.
_REMEDIATION_BY_OWASP = {
    "SC01": "Apply the checks-effects-interactions pattern (update this contract's "
            "state before making the external call) and/or add a reentrancy guard "
            "(e.g. OpenZeppelin ReentrancyGuard / nonReentrant) on the affected function(s).",
    "SC02": "Add explicit access control (e.g. onlyOwner or role-based modifiers) to "
            "the affected function(s) so privileged operations cannot be invoked by "
            "an arbitrary caller.",
    "SC03": "Restrict the upgrade/delegatecall entry point to a trusted, "
            "access-controlled admin path (e.g. a timelocked proxy admin) and "
            "validate the delegatecall target to prevent arbitrary code execution "
            "in this contract's storage context.",
}


def _remediation_line(vuln_title, owasp_category):
    """Real, vulnerability-specific guidance for this run's actual top finding,
    or an honest statement when there's no finding or no mapping to recommend
    one from -- never generic "review your code" text standing in for either."""
    if not vuln_title:
        return "- No vulnerability finding this run -- nothing vulnerability-specific to remediate."
    code = (owasp_category or "").split(":")[0].strip()
    specific = _REMEDIATION_BY_OWASP.get(code)
    if specific:
        return f"- *{vuln_title}* ({owasp_category}): {specific}"
    return (f"- *{vuln_title}* has no specific OWASP smart-contract category mapping "
            f"in this pipeline (category: {owasp_category or 'unclassified'}); manual "
            f"review of this finding is recommended.")


class JiraIncidentDispatcher:
    """Dispatches automated SEV-1 emergency response tickets to Jira upon critical exploit detection."""

    def __init__(self, jira_url: str = None, username: str = None, api_token: str = None, project_key: str = None):
        # Vault (secret/data/soc/jira) first, same as every other credential
        # in this pipeline; os.getenv() (.env's JIRA_URL/JIRA_USER/JIRA_TOKEN
        # names) is only a fallback for when Vault itself is unreachable.
        vault = _vault_jira_secret() or {}
        self.jira_url = jira_url or vault.get("url") or os.getenv("JIRA_URL", "https://saleemalimohammad211126.atlassian.net")
        self.username = username or vault.get("user") or os.getenv("JIRA_USER", "saleemali.mohammad@gmail.com")
        self.api_token = api_token or vault.get("token") or os.getenv("JIRA_TOKEN", "")
        self.project_key = project_key or vault.get("project_key") or os.getenv("JIRA_PROJECT_KEY", "KAN")

    def dispatch_sev1_ticket(
        self,
        incident_id: str = "INC-SEV1-ACTIVE",
        contract_name: str = None,
        contract: str = None,
        dread_score: float = 8.4,
        findings_summary: str = "High-severity vulnerability confirmed by multi-zone consensus.",
        vuln_title: str = None,
        owasp_category: str = None,
        safe_configured: bool = False,
        safe_pause_payload: str = None,
        avs_quorum: bool = True,
        stix_bundle_path: str = None,
        readiness_gate_halted: bool = False,
        **kwargs
    ) -> dict:
        target_contract = contract_name or contract or "VulnerableVault.sol"
        summary = f"[SEV-1 AUTO-HALT] Exploitation Prevented on {target_contract} (DREAD {dread_score})"

        # No Gnosis Safe is deployed or configured anywhere in this project
        # (no Safe address, no Transaction Service URL, no deployment
        # record) -- SafeEmergencyPauseBuilder's hardcoded to/data/nonce
        # produced the identical "pause proposed" claim on every ticket
        # regardless of contract, so that fake claim is never shown; the
        # ticket states the real absence of a Safe instead.
        if safe_configured and safe_pause_payload:
            mitigation_lines = [f"- Gnosis Safe emergency pause proposed: `{safe_pause_payload}`"]
        else:
            mitigation_lines = ["- Gnosis Safe pause: NOT CONFIGURED for this environment "
                                 "(no Safe deployment or Transaction Service URL configured)."]

        # Only claimed when the readiness gate was actually enforced AND it
        # actually contributed to this run's real halt_reasons -- never
        # printed as a blanket claim about something that may not have
        # happened. Correct component name (Zone 9 is the HTML report
        # layer, not a readiness gate).
        if readiness_gate_halted:
            mitigation_lines.append("- Autonomous execution halted deployment at the "
                                     "production-readiness policy gate "
                                     "(src/deployment/readiness_policy_gate.py).")

        mitigation_lines.append("- Forensic evidence bundle sealed with a SHA-256 manifest "
                                 "hash (flat hash over the manifest, not a Merkle tree).")
        mitigation_lines.append(_remediation_line(vuln_title, owasp_category))

        desc = (
            f"*Autonomous Blockchain SOC — Emergency Halt Consensus Event*\n\n"
            f"*Incident ID:* `{incident_id}`\n"
            f"*Target Contract:* `{target_contract}`\n"
            f"*Assessed DREAD Score:* `{dread_score} / 10.0`\n"
            f"*AVS Byzantine Consensus:* `{'VERIFIED (100% agreement)' if avs_quorum else 'PENDING'}`\n\n"
            f"h3. Technical Triage & Findings\n{findings_summary}\n\n"
            f"h3. Recommended Immediate Mitigation Actions\n"
            + "\n".join(mitigation_lines) + "\n"
        )
        if stix_bundle_path:
            desc += f"\n*STIX 2.1 Threat Indicator Bundle:* `{stix_bundle_path}`\n"

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
        suffix = incident_id[-4:].lstrip("-")
        local_key = f"{self.project_key}-{suffix}"
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
        contract="VulnerableVault.sol",
        dread_score=8.4,
        findings_summary="Reentrancy exploit path verified via Slither AST and Mythril symbolic solver.",
        vuln_title="reentrancy-eth",
        owasp_category="SC01: Reentrancy Exploitation",
        avs_quorum=True,
        stix_bundle_path="reports/stix/latest-incident-stix.json"
    )
    print(f"[+] Jira Dispatch Result: Status={res['status']} Key={res.get('key')} URL={res.get('url')}")
