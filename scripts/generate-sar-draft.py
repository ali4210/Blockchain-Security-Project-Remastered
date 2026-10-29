#!/usr/bin/env python3
"""Zone 5 draft SAR (Suspicious Activity Report) generation, driven by this
run's REAL verdict, SAST finding, and OFAC screening result.

Trigger: only runs the real generator when reports/verdict.json's verdict is
REAL HALT for this run -- the same real signal Zone 4's Jira/TheHive incident
response (run-incident-abort.py) already keys off. A PASS/UNKNOWN run is not
a suspicious-activity case, so no draft is produced (not_run, not a faked
empty one).

HONEST SCOPE:
  * This pipeline does not monitor live on-chain transactions (no AML
    telemetry source is wired into run-all-e2e.sh), so `transactions` and
    `transaction_hashes` are genuinely empty here -- never a fabricated
    tx hash. The suspicious-activity narrative is built from this run's real
    SAST top finding plus any real OFAC SDN match from
    reports/ofac-screening-report.json.
  * Output stays DRAFT_PENDING_REVIEW / LOCAL_STAGING_ONLY, matching
    sar_generator.py's own human-in-the-loop guarantee -- nothing here files
    anything externally.
"""
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

sys.path.insert(0, str(REPO_ROOT / "scripts" / "lib"))
from scanner_result import write_result  # noqa: E402

from src.compliance.sar_generator import (  # noqa: E402
    SARReportGenerator,
    InvolvedSubject,
)

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


def flagged_subjects(ofac_report):
    subjects = []
    for row in (ofac_report or {}).get("screened", []):
        if row.get("flagged"):
            subjects.append(InvolvedSubject(
                address=row["address"],
                role="SCREENED_COUNTERPARTY",
                risk_tier=row.get("risk_tier", "CRITICAL_SANCTIONED"),
                sanction_category=row.get("entity"),
            ))
    return subjects


def main():
    verdict_doc = _read_json("reports/verdict.json") or {}
    verdict = verdict_doc.get("verdict", "UNKNOWN")
    if verdict != "HALT":
        print(f"[+] [ZONE 5] Draft SAR generation: SKIPPED (pipeline verdict is {verdict}, not HALT)")
        return write_result("sar-draft", "sar-generator", "not_run",
                            detail=f"pipeline verdict was {verdict}, not HALT; no suspicious-activity case this run")

    target = os.environ.get("TARGET_CONTRACT", verdict_doc.get("target", "unknown"))
    target_name = Path(target).name
    case_id = f"SAR-{verdict_doc.get('generated_at', 'unknown').replace(':', '').replace('-', '')}"

    sast = _read_json("reports/sast-symbolic-report.json")
    tf = top_finding(sast)
    ofac = _read_json("reports/ofac-screening-report.json")
    subjects = flagged_subjects(ofac)

    findings = [{
        "risk_type": "PIPELINE_HALT_EXPLOIT",
        "rule_id": (tf.get("check") if tf else "halt-verdict"),
        "description": reason,
    } for reason in verdict_doc.get("halt_reasons", [])]

    if subjects:
        findings.append({
            "risk_type": "OFAC_SANCTIONS_MATCH",
            "rule_id": "ofac-sdn-screening",
            "description": (f"{len(subjects)} address(es) matched the OFAC SDN snapshot during this "
                            f"run's screening of {target_name}'s counterparties."),
        })

    print(f"\n[+] [ZONE 5] Draft SAR generation for {target_name} (case {case_id})...")
    try:
        draft = SARReportGenerator().generate_draft(
            case_id=case_id,
            findings=findings,
            subjects=subjects,
            transactions=[],
        )
    except Exception as exc:  # noqa: BLE001
        print(f"    -> not_run: {exc}")
        return write_result("sar-draft", "sar-generator", "not_run", detail=str(exc)[:250])

    verified = SARReportGenerator.verify_draft_integrity(draft)
    report = {
        "report_id": draft.report_id,
        "created_at_utc": draft.created_at_utc,
        "status": draft.status.value,
        "jurisdiction": draft.jurisdiction.value,
        "case_summary": draft.case_summary,
        "typologies_detected": draft.typologies_detected,
        "subjects": draft.subjects,
        "transaction_hashes": draft.transaction_hashes,
        "total_suspicious_volume_wei": draft.total_suspicious_volume_wei,
        "narrative": draft.narrative,
        "draft_digest": draft.draft_digest,
        "requires_human_approval": draft.requires_human_approval,
        "filing_channel": draft.filing_channel,
        "digest_verified": verified,
    }
    report_file = REPO_ROOT / "reports" / "sar-draft-report.json"
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(f"    -> report_id={draft.report_id} status={draft.status.value} "
          f"typologies={draft.typologies_detected}")
    print(f"    -> subjects={len(draft.subjects)} digest_verified={verified} "
          f"filing_channel={draft.filing_channel}")

    return write_result("sar-draft", "sar-generator", "ok" if verified else "error",
                        counts={"typologies": len(draft.typologies_detected),
                                "subjects": len(draft.subjects)},
                        raw_report=report_file,
                        detail=f"draft SAR {draft.report_id}, DRAFT_PENDING_REVIEW, digest_verified={verified}")


if __name__ == "__main__":
    main()
