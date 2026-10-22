#!/usr/bin/env python3
"""Ingest a TheHive case built from this run's REAL incident data.

No hardcoded API key, no fixed case narrative, no pre-completed tasks, and no
"success" line that isn't backed by a real API status code. The API key comes
from THEHIVE_API_KEY or Vault (secret/data/soc/thehive); with neither, ingestion is
skipped honestly (exit 0, reported as not performed) rather than posting with a
baked-in credential.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import write_result  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
THEHIVE_BASE = os.environ.get("THEHIVE_BASE", os.environ.get("THEHIVE_URL", "http://127.0.0.1:9005"))
ORG = os.environ.get("THEHIVE_ORG", "Blockchain-SOC")
VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN")


def resolve_api_key():
    key = os.environ.get("THEHIVE_API_KEY")
    if key:
        return key, "env"
    if VAULT_TOKEN:
        try:
            r = requests.get(f"{VAULT_ADDR}/v1/secret/data/soc/thehive",
                             headers={"X-Vault-Token": VAULT_TOKEN}, timeout=5)
            if r.status_code == 200:
                k = r.json().get("data", {}).get("data", {}).get("api_key")
                if k:
                    return k, "vault"
        except Exception:
            pass
    return None, None


def read_json(rel):
    p = REPO_ROOT / rel
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return None
    return None


def main():
    api_key, key_src = resolve_api_key()
    if not api_key:
        print("[*] [THEHIVE] no THEHIVE_API_KEY (env or Vault secret/data/soc/thehive); "
              "skipping case ingestion (not performed)")
        write_result("thehive", "thehive", "not_run",
                     detail="no THEHIVE_API_KEY (env or Vault secret/data/soc/thehive)")
        return 0

    headers = {"Authorization": f"Bearer {api_key}", "X-Organisation": ORG,
               "Content-Type": "application/json"}

    # --- real run context ------------------------------------------------
    target_contract = os.getenv("TARGET_CONTRACT", "contracts/solidity/VulnerableVault.sol")
    target_filename = Path(target_contract).name
    incident_id = os.getenv("INCIDENT_ID", "INC-UNSPECIFIED")
    evidence_sha = os.getenv("INCIDENT_EVIDENCE_SHA256", "")
    top_finding = os.getenv("INCIDENT_TOP_FINDING", "")
    flagged_addr = os.getenv("INCIDENT_FLAGGED_ADDRESS", "").strip()

    verdict = read_json("reports/verdict.json") or {}
    avs = read_json("reports/scanners/avs-consensus.json") or {}
    sast = read_json("reports/sast-symbolic-report.json") or {}

    stix_path = REPO_ROOT / "reports" / "stix" / "latest-incident-stix.json"
    bundle_hash = ""
    if stix_path.is_file():
        bundle_hash = hashlib.sha256(stix_path.read_bytes()).hexdigest()

    verdict_str = verdict.get("verdict", "UNKNOWN")
    halt_reasons = verdict.get("halt_reasons", [])
    findings = sast.get("findings", [])
    high = [f for f in findings if (f.get("impact") or "").upper() in ("HIGH", "CRITICAL")]
    # Severity from the real verdict/findings, not a fixed constant.
    severity = 3 if (verdict_str == "HALT" or high) else 1

    avs_line = (f"{avs.get('final_verdict', 'n/a')} "
                f"(supermajority_exploit={avs.get('supermajority_exploit')})"
                if avs else "not available")

    case_desc = (
        f"### Autonomous Blockchain SOC incident record\n"
        f"- **Incident**: `{incident_id}`\n"
        f"- **Target**: `{target_contract}`\n"
        f"- **Pipeline verdict**: `{verdict_str}`"
        + (f" — reasons: {'; '.join(halt_reasons)}" if halt_reasons else "") + "\n"
        f"- **Top SAST finding**: `{top_finding or 'none'}`; "
        f"{len(high)} high/critical of {len(findings)} total\n"
        f"- **AVS consensus**: {avs_line}\n"
        f"- **Sealed evidence root SHA-256**: `{evidence_sha or 'n/a'}`\n"
        f"- **STIX bundle SHA-256**: `{bundle_hash or 'n/a'}`\n"
        + (f"- **OFAC-flagged address**: `{flagged_addr}`\n" if flagged_addr else
           "- **OFAC screening**: no flagged address this run\n")
    )
    case_title = (f"{'INCIDENT' if severity > 1 else 'AUDIT'}: {target_filename} "
                  f"({verdict_str})")
    tags = ["blockchain-soc", "stix-2.1", f"verdict-{verdict_str.lower()}"]
    if flagged_addr:
        tags.append("ofac-flagged")

    case_payload = {"title": case_title, "description": case_desc, "severity": severity,
                    "flag": severity > 1, "tlp": 2, "pap": 2, "tags": tags}

    print(f"[*] [THEHIVE] creating case at {THEHIVE_BASE} (key from {key_src})...")
    try:
        res = requests.post(f"{THEHIVE_BASE}/api/case", json=case_payload, headers=headers, timeout=10)
    except Exception as exc:
        print(f"[-] [THEHIVE] unreachable: {str(exc)[:150]}")
        write_result("thehive", "thehive", "error", detail=f"unreachable: {str(exc)[:150]}")
        return 1
    if res.status_code not in (200, 201):
        print(f"[-] [THEHIVE] case creation failed: HTTP {res.status_code} {res.text[:200]}")
        write_result("thehive", "thehive", "error",
                     detail=f"case creation failed: HTTP {res.status_code} {res.text[:200]}")
        return 1

    data = res.json()
    cid = data.get("_id") or data.get("id")
    print(f"[+] [THEHIVE] case created: id={cid} caseId={data.get('caseId')}")

    # Observables: only real artifacts from this run.
    observables = []
    if bundle_hash:
        observables.append({"dataType": "hash", "data": bundle_hash,
                            "message": "STIX 2.1 bundle SHA-256", "ioc": True, "tags": ["stix"]})
    if evidence_sha:
        observables.append({"dataType": "hash", "data": evidence_sha,
                            "message": "Sealed evidence manifest root SHA-256", "ioc": False,
                            "tags": ["rfc-3227", "custody"]})
    if flagged_addr:
        observables.append({"dataType": "other", "data": flagged_addr,
                            "message": "OFAC SDN flagged address (screened this run)",
                            "ioc": True, "tags": ["ofac"]})
    created_obs = 0
    for obs in observables:
        try:
            o = requests.post(f"{THEHIVE_BASE}/api/case/{cid}/artifact", json=obs, headers=headers, timeout=10)
            if o.status_code in (200, 201, 207):
                created_obs += 1
        except Exception:
            pass

    # Tasks: all start open. Nothing is pre-marked Completed — a task is only
    # closed when a human actually does it.
    tasks = [
        {"title": "TASK-01: Verify Gnosis Safe circuit-breaker execution", "status": "InProgress"},
        {"title": "TASK-02: Confirm OFAC screening result and counterparties", "status": "Waiting"},
        {"title": "TASK-03: Validate Slither/Mythril findings and remediation", "status": "Waiting"},
        {"title": "TASK-04: RFC 3227 evidence custody verification", "status": "Waiting"},
    ]
    created_tasks = 0
    for t in tasks:
        try:
            r = requests.post(f"{THEHIVE_BASE}/api/case/{cid}/task", json=t, headers=headers, timeout=10)
            if r.status_code in (200, 201):
                created_tasks += 1
        except Exception:
            pass

    print(f"[+] [THEHIVE] created {created_obs}/{len(observables)} observable(s), "
          f"{created_tasks}/{len(tasks)} task(s) (none pre-completed)")
    write_result("thehive", "thehive", "ok",
                 counts={"observables_created": created_obs, "observables_total": len(observables),
                         "tasks_created": created_tasks, "tasks_total": len(tasks)},
                 detail=f"case {cid} (caseId={data.get('caseId')}): {case_title}",
                 extra={"case_id": cid, "case_number": data.get("caseId")})
    return 0


if __name__ == "__main__":
    sys.exit(main())
