#!/usr/bin/env python3
"""Zone 4/5 incident response, driven by this run's REAL scan data.

No fixed incident narrative: the STIX bundle, the sealed evidence hash, and the
Jira ticket are all built from the actual target, findings, verdict and sealed
evidence of this run. Jira status is whatever the dispatcher really returned.
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.incident.safe_pause_builder import SafeEmergencyPauseBuilder
from src.incident.jira_dispatcher import JiraIncidentDispatcher
from src.forensics.stix_exporter import Stix21BundleExporter
from src.forensics.evidence_sealer import seal_run_evidence
from src.forensics.evidence_db import EvidenceDatabaseManager

# Transparent impact -> DREAD-style score, derived from the real top finding.
IMPACT_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0,
                "INFORMATIONAL": 1.0, "INFO": 1.0}
IMPACT_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1, "INFO": 1}


def _read_json(rel):
    p = REPO_ROOT / rel
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return None
    return None


def top_finding(sast):
    findings = (sast or {}).get("findings", [])
    if not findings:
        return None
    return max(findings, key=lambda f: IMPACT_RANK.get((f.get("impact") or "").upper(), 0))


def flagged_address():
    """A real OFAC-flagged address from this run, or None. Never a hardcoded one."""
    rep = _read_json("reports/ofac-screening-report.json")
    for row in (rep or {}).get("screened", []):
        if row.get("flagged"):
            return row.get("address")
    return None


def main():
    target = os.getenv("TARGET_CONTRACT", "contracts/solidity/VulnerableVault.sol")
    target_name = Path(target).name
    incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}"

    sast = _read_json("reports/sast-symbolic-report.json")
    verdict = _read_json("reports/verdict.json") or {}
    tf = top_finding(sast)
    vuln_title = tf.get("check") if tf else "no-finding"
    impact = (tf.get("impact") if tf else "INFORMATIONAL").upper()
    owasp = (tf.get("owasp_category", "").split(":")[0] or "SC01") if tf else "SC01"
    dread = IMPACT_SCORE.get(impact, 0.0)

    print(f"\n[+] [ZONE 4] Incident response for {target_name} (incident {incident_id})")
    print(f"    -> top finding: {vuln_title} [{impact}] | pipeline verdict: {verdict.get('verdict', 'UNKNOWN')}")

    # 1. Gnosis Safe emergency pause calldata (real builder)
    safe_tx = SafeEmergencyPauseBuilder().build_pause_calldata()
    print(f"    -> Gnosis Safe pause payload: to={safe_tx.get('to')} data={safe_tx.get('data')}")

    # 2. Seal this run's REAL evidence -> real root digest (changes with content)
    seal = seal_run_evidence(REPO_ROOT, incident_id)
    try:
        db = EvidenceDatabaseManager(str(REPO_ROOT / "data" / "forensics.db"))
        db.register_evidence(
            evidence_id=seal["incident_id"] + "-manifest",
            file_path=seal["manifest_path"],
            byte_size=seal["manifest_bytes"],
            sha256=seal["root_sha256"], sha512=seal["root_sha512"], status="SEALED")
    except Exception as exc:  # DB issues must not fabricate a seal
        print(f"    [-] evidence DB seal warning: {str(exc)[:100]}")
    print(f"    -> Sealed {seal['file_count']} real evidence file(s); "
          f"root SHA-256: {seal['root_sha256'][:24]}...")

    # 3. STIX 2.1 bundle built from the REAL target/finding/evidence
    print("\n[+] [ZONE 5] Exporting STIX 2.1 bundle from real scan data...")
    stix_path = Stix21BundleExporter().create_incident_bundle(
        incident_id=incident_id,
        target_contract=target,
        vulnerability_title=vuln_title,
        dread_score=dread,
        evidence_sha256=seal["root_sha256"],
        attacker_or_flagged_address=flagged_address(),  # None unless a real match
        owasp_id=owasp)
    print(f"    -> STIX bundle: {stix_path}")

    # 4. Jira SEV-1 dispatch — report the REAL result, no fabricated success
    findings_summary = (f"{vuln_title} [{impact}] in {target_name}; "
                        f"pipeline verdict {verdict.get('verdict', 'UNKNOWN')}")
    ticket = JiraIncidentDispatcher().dispatch_sev1_ticket(
        incident_id=incident_id, contract=target_name, dread_score=dread,
        findings_summary=findings_summary,
        safe_pause_payload=safe_tx.get("data"),
        avs_quorum=bool((_read_json("reports/scanners/avs-consensus.json") or {})
                        .get("supermajority_exploit")),
        stix_bundle_path=str(stix_path))
    print(f"    -> Jira: status={ticket.get('status')} key={ticket.get('key')}"
          + (f" url={ticket.get('url')}" if ticket.get("url") else " (no live dispatch; recorded locally)"))

    # 5. TheHive case ingestion — pass real context, report real status
    print("\n[+] [ZONE 5] Ingesting case into TheHive...")
    env = {**os.environ,
           "INCIDENT_ID": incident_id,
           "INCIDENT_EVIDENCE_SHA256": seal["root_sha256"],
           "INCIDENT_TOP_FINDING": f"{vuln_title}|{impact}",
           "INCIDENT_FLAGGED_ADDRESS": flagged_address() or ""}
    proc = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "ingest-thehive-incident.py")],
                          capture_output=True, text=True, env=env)
    for line in (proc.stdout or "").strip().splitlines():
        print(f"    {line}")
    if proc.returncode != 0 and proc.stderr:
        print(f"    [-] TheHive stderr: {proc.stderr.strip()[:200]}")


if __name__ == "__main__":
    main()
