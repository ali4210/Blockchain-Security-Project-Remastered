#!/usr/bin/env python3
import os
import sys
import requests
import json
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import write_result  # noqa: E402

def scanner_ok(name):
    """Only ingest evidence from scanners that really ran in THIS run."""
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", "scanners", name + ".json")
    try:
        return json.load(open(p)).get("status") == "ok"
    except (OSError, ValueError):
        return False

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(PROJECT_ROOT, "config", ".defectdojo.env")

if os.path.isfile(ENV_FILE):
    with open(ENV_FILE, "r") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                os.environ.setdefault(k, v.strip('"\''))

DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://127.0.0.1:8085")
DEFECTDOJO_TOKEN = os.environ.get("DEFECTDOJO_TOKEN")
if not DEFECTDOJO_TOKEN:
    print("[-] [DEFECTDOJO] DEFECTDOJO_TOKEN not set (env or config/.defectdojo.env); skipping ingestion")
    write_result("defectdojo", "defectdojo", "not_run", detail="no DEFECTDOJO_TOKEN (env or config/.defectdojo.env)")
    sys.exit(0)

HEADERS = {"Authorization": f"Token {DEFECTDOJO_TOKEN}"}

def get_or_create(endpoint, query_param, name, create_payload):
    res = requests.get(f"{DEFECTDOJO_URL}/api/v2/{endpoint}/?{query_param}={name}", headers=HEADERS).json()
    if res.get("count", 0) > 0:
        return res["results"][0]["id"]
    create_res = requests.post(f"{DEFECTDOJO_URL}/api/v2/{endpoint}/", headers=HEADERS, json=create_payload).json()
    return create_res["id"]

def upload_scan(engagement_id, scan_type, file_path):
    if not os.path.isfile(file_path):
        return False
    
    print(f"[+] [DEFECTDOJO] Ingesting {scan_type} ({os.path.basename(file_path)})...")
    # Always send UTC date to prevent 'scan_date cannot be in the future' errors
    today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    url = f"{DEFECTDOJO_URL}/api/v2/import-scan/"
    
    with open(file_path, "rb") as fp:
        data = {
            "engagement": engagement_id,
            "scan_type": scan_type,
            "scan_date": today_utc,
            "active": True,
            "verified": False,
            "close_old_findings": True,
            "auto_create_context": True
        }
        res = requests.post(url, headers=HEADERS, data=data, files={"file": fp})
        if res.status_code in [200, 201]:
            print(f"[+] [DEFECTDOJO] Successfully ingested {scan_type}.")
            return True
        else:
            print(f"[-] [DEFECTDOJO] Import failed for {scan_type} ({res.status_code}): {res.text}")
            return False

def _scanner_json(name):
    """Read a real reports/scanners/<name>.json result, or None if absent."""
    p = os.path.join(PROJECT_ROOT, "reports", "scanners", name + ".json")
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return None


def _severity_label(impact):
    """Normalize this pipeline's various impact spellings to DefectDojo's
    Critical/High/Medium/Low/Info severity choices."""
    s = (impact or "").upper()
    return {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
            "LOW": "Low", "INFORMATIONAL": "Info", "INFO": "Info"}.get(s, "Info")


def build_mythril_findings():
    """Real Mythril findings already present in reports/sast-symbolic-report.json
    (the same file pipeline-verdict.py reads) -- never uploaded until now
    because only Slither's SARIF was wired into DefectDojo."""
    sast_path = os.path.join(PROJECT_ROOT, "reports/sast-symbolic-report.json")
    if not os.path.isfile(sast_path):
        return []
    sast = json.load(open(sast_path))
    out = []
    for f in sast.get("findings", []):
        if f.get("engine") != "Mythril":
            continue
        out.append({
            "title": f"[Mythril] {f.get('check')}",
            "description": f.get("description") or "",
            "severity": _severity_label(f.get("impact")),
            "references": f.get("swc", ""),
        })
    return out


def build_openscap_findings():
    """Real failed SCAP rules from the raw results XML. Only ever produces
    anything on a host where OpenSCAP genuinely scored rules (status == ok);
    on a platform/profile mismatch (this host) there is nothing to report,
    same honest gating as every other scanner_ok()-gated upload here."""
    raw_path = os.path.join(PROJECT_ROOT, "reports/raw/oscap-results.xml")
    if not os.path.isfile(raw_path):
        return []
    out = []
    try:
        root = ET.parse(raw_path).getroot()
        for rr in root.findall(".//{*}rule-result"):
            if (rr.findtext("{*}result") or "").strip() != "fail":
                continue
            rule_id = rr.get("idref", "unknown-rule")
            out.append({
                "title": f"[OpenSCAP] {rule_id}",
                "description": f"SCAP rule {rule_id} failed evaluation.",
                "severity": "Medium",
            })
    except ET.ParseError:
        pass
    return out


def build_sca_findings():
    """One summary finding from the real counts in reports/scanners/sca.json
    (no itemized per-package advisory list exists in this pipeline's output,
    only aggregate counts -- so that's what gets reported, honestly)."""
    res = _scanner_json("sca") or {}
    counts = res.get("counts", {})
    crit = counts.get("npmAuditCritical", 0)
    high = counts.get("npmAuditHigh", 0)
    if crit + high == 0:
        return []
    return [{
        "title": f"npm audit: {crit} critical / {high} high advisories",
        "description": (f"{counts.get('activeAdvisories', 0)} active advisories across "
                        f"{counts.get('matchedPackages', 0)} matched package(s)."),
        "severity": "Critical" if crit else "High",
    }]


def build_sonar_findings():
    """One summary finding when the real SonarQube quality gate is ERROR."""
    res = _scanner_json("sonar") or {}
    if res.get("gate") != "ERROR":
        return []
    return [{
        "title": f"SonarQube quality gate: ERROR ({res.get('project', 'unknown project')})",
        "description": res.get("detail") or "",
        "severity": "Medium",
    }]


def build_readiness_findings():
    """One summary finding when the real production-readiness gate blocks."""
    res = _scanner_json("readiness") or {}
    if res.get("decision") != "block":
        return []
    return [{
        "title": "Production readiness gate: BLOCK",
        "description": res.get("detail") or "",
        "severity": "High",
    }]


def build_avs_findings():
    """One finding when the real 3-node AVS consensus confirms an exploit."""
    res = _scanner_json("avs-consensus") or {}
    if not res.get("supermajority_exploit"):
        return []
    return [{
        "title": f"AVS consensus: {res.get('final_verdict', 'EXPLOIT_PROVEN')}",
        "description": res.get("detail") or "",
        "severity": "Critical",
    }]


def build_swarm_findings():
    """One finding when the real 7-agent LangGraph swarm confirms a halt."""
    res = _scanner_json("swarm") or {}
    if res.get("decision") != "HALT_CONFIRMED":
        return []
    return [{
        "title": f"LangGraph swarm consensus: {res.get('decision')}",
        "description": res.get("detail") or "",
        "severity": "High",
    }]


def build_ofac_findings():
    """One finding per real OFAC SDN match from this run's screening."""
    p = os.path.join(PROJECT_ROOT, "reports/ofac-screening-report.json")
    if not os.path.isfile(p):
        return []
    data = json.load(open(p))
    out = []
    for row in data.get("screened", []):
        if not row.get("flagged"):
            continue
        out.append({
            "title": f"OFAC SDN match: {row.get('entity') or 'unknown entity'}",
            "description": row.get("reason") or "",
            "severity": "Critical",
        })
    return out


def build_sar_findings():
    """One finding for the real draft SAR this run produced (only exists when
    the real pipeline verdict was HALT -- see scripts/generate-sar-draft.py)."""
    p = os.path.join(PROJECT_ROOT, "reports/sar-draft-report.json")
    if not os.path.isfile(p):
        return []
    data = json.load(open(p))
    return [{
        "title": f"Draft SAR generated: {data.get('report_id')}",
        "description": (f"{data.get('case_summary')} Status={data.get('status')}, "
                        f"filing_channel={data.get('filing_channel')} (requires human review "
                        "before any external filing)."),
        "severity": "High",
    }]


def _consensus_severity(sev):
    """CRITICAL_FINALITY_VIOLATION / CRITICAL_ATTACK / etc aren't in
    _severity_label's exact word set, so map on substring instead."""
    s = (sev or "").upper()
    if "CRITICAL" in s:
        return "Critical"
    if "WARNING" in s or "SUSPECTED" in s or "SHALLOW" in s:
        return "Medium"
    return "High"


def build_consensus_attack_findings():
    """One finding per real triggered check from chain_attack_monitor.py's
    reports/consensus-attack-findings.json (Section A: reorg / concentration /
    eclipse / selfish-mining, fed from a real forced Anvil reorg)."""
    p = os.path.join(PROJECT_ROOT, "reports/consensus-attack-findings.json")
    if not os.path.isfile(p):
        return []
    out = []
    for f in json.load(open(p)):
        if not f.get("triggered"):
            continue
        sev = f.get("severity") or f.get("threat_level") or ""
        out.append({
            "title": f"Consensus-attack: {f.get('metric')} triggered",
            "description": f"observed={f.get('observed_value')} threshold={f.get('threshold')} "
                           f"{f.get('note', '')}".strip(),
            "severity": _consensus_severity(sev),
        })
    return out


def build_flashloan_findings():
    """One finding per real flash-loan-shape / front-running finding from
    src/defi/flashloan_detector.py's reports/flashloan-findings.json (Section B)."""
    p = os.path.join(PROJECT_ROOT, "reports/flashloan-findings.json")
    if not os.path.isfile(p):
        return []
    out = []
    for t in json.load(open(p)).get("targets", []):
        for f in t.get("flashloan_findings", []):
            out.append({"title": f"Flash-loan attack shape: {f.get('function')}()",
                        "description": f.get("detail", ""), "severity": "High"})
        for f in t.get("frontrunning_findings", []):
            out.append({"title": f"Front-running exposure: {f.get('function')}()",
                        "description": f.get("detail", ""), "severity": "Medium"})
    return out


def build_rugpull_findings():
    """One finding per real FAILING rug-pull check from
    src/defi/rugpull_detector.py's reports/rugpull-findings.json (Section C).
    NOT_APPLICABLE/pass checks are not findings -- only genuine fails are."""
    p = os.path.join(PROJECT_ROOT, "reports/rugpull-findings.json")
    if not os.path.isfile(p):
        return []
    out = []
    for t in json.load(open(p)).get("targets", []):
        for c in t.get("checks", []):
            if c.get("result") != "fail":
                continue
            out.append({"title": f"Rug-pull risk: {c.get('check')}",
                        "description": c.get("justification", ""), "severity": "High"})
    return out


def build_echidna_findings():
    """One finding per real FALSIFIED Echidna property from this run's actual
    reports/echidna-report.json (Section F). A real, fuzzer-found
    counterexample on the intentionally vulnerable default fixture is an
    expected result, same honesty bar as avs-consensus/swarm above."""
    p = os.path.join(PROJECT_ROOT, "reports/echidna-report.json")
    if not os.path.isfile(p):
        return []
    out = []
    for prop in json.load(open(p)).get("properties", []):
        if prop.get("passed"):
            continue
        out.append({"title": f"Echidna property falsified: {prop.get('name')}",
                    "description": prop.get("detail", ""), "severity": "High"})
    return out


def build_vyper_findings():
    """One finding per real reentrancy-shaped finding from this run's actual
    reports/vyper-check-report.json (Section E)."""
    p = os.path.join(PROJECT_ROOT, "reports/vyper-check-report.json")
    if not os.path.isfile(p):
        return []
    out = []
    for f in json.load(open(p)).get("reentrancy_shaped_findings", []):
        out.append({"title": f"Vyper reentrancy-shaped exposure: {f.get('function')}()",
                    "description": f.get("detail", ""), "severity": "High"})
    return out


def upload_generic_findings(engagement_id, name, findings):
    """Write this run's real findings to DefectDojo's Generic Findings Import
    endpoint (verified live: scan_type="Generic Findings Import" accepts
    {"findings": [{"title","description","severity"}, ...]})."""
    if not findings:
        print(f"[*] [DEFECTDOJO] {name}: ran ok, nothing to report this run (clean).")
        return None
    print(f"[+] [DEFECTDOJO] {name}: {len(findings)} real finding(s) to report via Generic Findings Import...")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        json.dump({"findings": findings}, tf, indent=2)
        tmp_path = tf.name
    try:
        return upload_scan(engagement_id, "Generic Findings Import", tmp_path)
    finally:
        os.unlink(tmp_path)


def main():
    print(f"[+] [DEFECTDOJO] Connecting to compliance dashboard at {DEFECTDOJO_URL}...")
    try:
        pt_id = get_or_create("product_types", "name", "Blockchain", {"name": "Blockchain", "description": "Blockchain Infrastructure"})
        prod_id = get_or_create("products", "name", "Blockchain-SOC", {"name": "Blockchain-SOC", "description": "Autonomous SOC", "prod_type": pt_id})
        
        today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        eng_id = get_or_create("engagements", "name", "SOC-Continuous-Compliance", {
            "name": "SOC-Continuous-Compliance", "product": prod_id, "target_start": today_utc,
            "target_end": today_utc, "status": "In Progress", "engagement_type": "CI/CD"
        })

        results = {}
        # Gitleaks left as in the original pipeline (deliberately not changed yet)
        upload_scan(eng_id, "Gitleaks Scan", os.path.join(PROJECT_ROOT, "reports/gitleaks-report.json"))
        if scanner_ok("trivy"):
            results["trivy"] = upload_scan(eng_id, "Trivy Scan", os.path.join(PROJECT_ROOT, "reports/raw/trivy-report.json"))
        if scanner_ok("zap"):
            zap_xml = os.path.join(PROJECT_ROOT, "reports/dast/zap-report.xml")
            zap_json = os.path.join(PROJECT_ROOT, "reports/dast/zap-report.json")
            results["zap"] = upload_scan(eng_id, "ZAP Scan", zap_xml) or upload_scan(eng_id, "ZAP Scan", zap_json)
        if scanner_ok("slither"):
            # Slither's own SARIF (written by run-sast-symbolic.py); never a stale or hand-built file
            results["slither"] = upload_scan(eng_id, "SARIF", os.path.join(PROJECT_ROOT, "reports/sast-symbolic-report.sarif"))

        # Generic-findings scanners: real per-run data, built from whatever
        # reports/scanners/<name>.json (or the raw report it points at) this
        # run actually produced. A scanner that ran ok but had nothing to
        # report (e.g. readiness passed, no OFAC match) is "clean", not
        # "skipped" or "failed" -- those are three different real states.
        generic_scanners = [
            ("mythril", build_mythril_findings),
            ("openscap", build_openscap_findings),
            ("sca", build_sca_findings),
            ("sonar", build_sonar_findings),
            ("readiness", build_readiness_findings),
            ("avs-consensus", build_avs_findings),
            ("swarm", build_swarm_findings),
            ("ofac-screening", build_ofac_findings),
            ("sar-draft", build_sar_findings),
            ("consensus-attack", build_consensus_attack_findings),
            ("flashloan-detector", build_flashloan_findings),
            ("rugpull-detector", build_rugpull_findings),
            ("echidna", build_echidna_findings),
            ("vyper-check", build_vyper_findings),
        ]
        not_run, clean = [], []
        for name, builder in generic_scanners:
            if not scanner_ok(name):
                not_run.append(name)
                continue
            r = upload_generic_findings(eng_id, name, builder())
            if r is None:
                clean.append(name)
            else:
                results[name] = r

        skipped = [n for n in ("trivy", "zap", "slither") if n not in results] + not_run
        failed = [n for n, ok in results.items() if not ok]
        if clean:
            print(f"[*] [DEFECTDOJO] Clean (ran ok, nothing to report): {', '.join(clean)}")
        if skipped:
            print(f"[!] [DEFECTDOJO] Skipped (scanner did not run ok this run): {', '.join(skipped)}")
        if failed:
            print(f"[-] [DEFECTDOJO] Upload FAILED for: {', '.join(failed)}")
            write_result("defectdojo", "defectdojo", "error",
                         detail=f"upload failed for: {', '.join(failed)}",
                         extra={"engagement_id": eng_id})
            sys.exit(1)
        print("[+] [DEFECTDOJO] Ingestion cycle finished (see skipped/failed lines above).")
        write_result("defectdojo", "defectdojo", "ok",
                     counts={"uploaded": len(results), "clean": len(clean), "skipped": len(skipped)},
                     detail=f"uploaded={list(results)}; clean={clean}; skipped={skipped}",
                     extra={"engagement_id": eng_id})
    except Exception as exc:
        print(f"[-] [DEFECTDOJO] Error communicating with DefectDojo: {exc}")
        write_result("defectdojo", "defectdojo", "error", detail=f"error communicating with DefectDojo: {exc}")

if __name__ == "__main__":
    main()
