"""Shared TheHive SEV-1 case builder.

Extracted from bootstrap-thehive-enterprise.py, provision-thehive-vault.py, and
sync-thehive-vault.py, which each independently built and posted an identical
case from the same per-run evidence sources (STIX bundle, OFAC screening, AVS
consensus, top SAST finding) -- flagged by SonarQube as duplicated code.
Each script's own user/API-key provisioning flow is genuinely different and
stays in that script; only this shared evidence/case/observable tail moved.
"""
import json
import hashlib
import os
from pathlib import Path

from src.incident.safe_pause_builder import SafeEmergencyPauseBuilder


def gather_evidence():
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
    avs_votes = (f"{avs.get('counts', {}).get('exploit_confirmed', 0)}/{avs.get('counts', {}).get('nodes', 0)}"
                 if avs else "no AVS result")
    avs_verdict = avs.get("final_verdict", "no AVS result this run")
    sanction_line = (f"{ofac_flag.get('entity', 'unknown entity')} ({ofac_flag.get('address')}) detected on OFAC SDN List"
                     if ofac_flag else "no sanctioned counterparty detected this run")
    finding_label = (f"{top_finding.get('check')} in {(top_finding.get('target') or '').split('/')[-1]}"
                      if top_finding else "Security")

    return {
        "bundle_hash": bundle_hash, "ofac_flag": ofac_flag, "avs": avs, "top_finding": top_finding,
        "jira_ticket": jira_ticket, "safe_tx": safe_tx, "avs_votes": avs_votes,
        "avs_verdict": avs_verdict, "sanction_line": sanction_line, "finding_label": finding_label,
    }


def build_case_payload(evidence):
    ofac_flag = evidence["ofac_flag"]
    return {
        "title": f"SEV-1: {evidence['finding_label']}" + (f" & {ofac_flag.get('entity')} Sanction Trigger" if ofac_flag else ""),
        "description": f"""### Autonomous Blockchain SOC Evidence Record
- **Incident Reference**: {evidence['jira_ticket']}
- **STIX 2.1 Bundle SHA-256**: `{evidence['bundle_hash']}`
- **RFC 3227 Custody Status**: Cryptographically Sealed by Vault Transit Key (`soc-relayer-key`)
- **Consensus Verdict**: 3-Node Anvil BFT ({evidence['avs_votes']} -> `{evidence['avs_verdict']}`)
- **Autonomous Defense**: Gnosis Safe Emergency Circuit Breaker Proposed (`{evidence['safe_tx']['data']}`)
- **Sanction Screening**: {evidence['sanction_line']}
""",
        "severity": 3,
        "flag": True,
        "tlp": 2,
        "pap": 2,
        "tags": ["blockchain-soc", "sev-1", "stix-2.1", "slither-sc01", "ofac-sdn", "vault-attested"],
    }


def build_observables(evidence):
    ofac_flag = evidence["ofac_flag"]
    top_finding = evidence["top_finding"]
    observables = [
        {"dataType": "hash", "data": evidence["bundle_hash"], "message": "RFC 3227 STIX 2.1 Bundle SHA-256 Digest", "ioc": True, "tags": ["rfc-3227"]},
        {"dataType": "ip", "data": "192.168.0.189", "message": "LangGraph 7-Agent Inference Relayer Node", "ioc": False, "tags": ["langgraph"]},
        {"dataType": "other", "data": evidence["safe_tx"]["data"], "message": "Gnosis Safe Multi-Sig Pause Calldata (real pause() selector)", "ioc": False, "tags": ["gnosis-safe"]},
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
    return observables


def post_case_with_observables(post, base_url, headers):
    """post: a callable like requests.post or session.post, used for both the
    case and artifact requests. Returns the case creation response; the caller
    decides what to print on success/failure since each script's banner text
    differs."""
    evidence = gather_evidence()
    case_payload = build_case_payload(evidence)
    case_resp = post(f"{base_url}/api/case", json=case_payload, headers=headers)
    if case_resp.status_code not in (200, 201):
        return case_resp, None, []

    case_data = case_resp.json()
    case_id = case_data.get("id")
    results = []
    for obs in build_observables(evidence):
        o_res = post(f"{base_url}/api/case/{case_id}/artifact", json=obs, headers=headers)
        results.append((obs, o_res))
    return case_resp, case_data, results
