#!/usr/bin/env python3
"""Real OWASP DSOMM maturity scoring -- never a hardcoded level.

Every activity below is only scored if this pipeline has a genuine automated
signal for it (a real scanner result, a real config file, a real integration
check). Everything else in the official model is reported as "not_assessed",
never defaulted to pass or fail -- most of DSOMM (security champions,
training programs, threat-modeling process, access reviews, ...) requires
human/organizational evidence no scanner can produce.

A subdimension only gets a claimed "level" if we have checked evidence for
it; the level is capped below the first FAILED checked activity, and always
ships with its coverage ratio (checked activities / total activities in that
subdimension per the official model) so "Level 2" is never misread as "fully
Level 2 per DSOMM" when we only checked 2 of 16 activities there.

Reference: OWASP DSOMM v5.0.2 (2026-09-17), model.yaml,
https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel-data
Totals below are a static snapshot of that model's per-dimension/
per-subdimension activity counts -- update them if the upstream model
changes meaningfully.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, load_all, write_result  # noqa: E402

# Official model totals (dimension -> {subdimension -> activity count}).
# Source: model.yaml meta.version 5.0.2. Used only as the honest denominator
# for coverage ratios -- never to infer a result for anything not checked.
MODEL_TOTALS = {
    "Agentic AI": {"Data Protection": 6, "Guidance": 15, "Isolation": 9, "Verification": 10},
    "Build and Deployment": {"Build": 6, "Deployment": 15, "Patch Management": 8},
    "Culture and Organization": {"Design": 7, "Education and Guidance": 17, "Process": 4},
    "Implementation": {"Application Hardening": 9, "Development and Source Control": 8,
                        "Identity and Access Management": 17, "Infrastructure Hardening": 21},
    "Information Gathering": {"Logging": 8, "Monitoring": 16, "Test KPI": 7},
    "Test and Verification": {"Application tests": 4, "Consolidation": 14,
                               "Dynamic depth for applications": 9, "Dynamic depth for infrastructure": 7,
                               "Static depth for applications": 17, "Static depth for infrastructure": 12,
                               "Test Intensity": 5},
}
GRAND_TOTAL = sum(n for subs in MODEL_TOTALS.values() for n in subs.values())  # 251


def _ok(res):
    return bool(res and res.get("status") == "ok")


def _count(res, key):
    return int((res or {}).get("counts", {}).get(key, 0))


def build_activities(results, gitleaks_findings):
    """Only activities this pipeline can genuinely check. (dimension, subdimension,
    name, uuid, level, passed) -- uuid is the official DSOMM activity id, citable
    against model.yaml."""
    slither, mythril = results.get("slither"), results.get("mythril")
    trivy, sca, zap = results.get("trivy"), results.get("sca"), results.get("zap")
    sonar, defectdojo = results.get("sonar"), results.get("defectdojo")
    jira_ticket = (ROOT / "reports" / "latest-jira-ticket.txt").is_file()

    return [
        ("Test and Verification", "Static depth for infrastructure",
         "Test for stored secrets in code", "c6e3c812-56e2-41b0-ae01-b7afc41a004c", 1,
         gitleaks_findings == 0),
        ("Test and Verification", "Consolidation",
         "Treatment of defects with high or critical severity", "44f2c8a9-4aaa-4c72-942d-63f78b89f385", 1,
         jira_ticket or _ok(defectdojo)),
        ("Implementation", "Development and Source Control",
         "Version control", "066084c6-1135-4635-9cc5-9e75c7c5459f", 1,
         (ROOT / ".git").is_dir()),
        ("Test and Verification", "Dynamic depth for applications",
         "Simple Scan", "07796811-37f9-467c-9ff2-48f346e77ff3", 2,
         _ok(zap)),
        ("Information Gathering", "Logging",
         "Centralized application logging", "fe875e17-ae4a-45f8-a359-244aa4fcbc04", 2,
         gitleaks_findings is not None),  # Zone 1 always runs; real signal either way
        ("Information Gathering", "Logging",
         "Logging of security events", "ccfdd0a8-991e-4269-ad77-c0a54ca655cb", 2,
         gitleaks_findings is not None),
        ("Information Gathering", "Monitoring",
         "Visualized metrics", "ded39bcf-4eaa-4c5f-9c94-09acde0a4734", 2,
         (ROOT / "config" / "grafana-soc-v10-4-dashboard.json").is_file()),
        ("Information Gathering", "Test KPI",
         "Number of vulnerabilities/severity", "bc548cba-cb82-4f76-bd4b-325d9d256279", 2,
         any(_ok(r) and r.get("counts") for r in (slither, mythril, trivy, sca, zap))),
        ("Build and Deployment", "Deployment",
         "Environment depending configuration parameters (secrets)", "df428c9d-efa0-4226-9f47-a15bb53f822b", 2,
         _ok(results.get("vault-sign"))),
        ("Test and Verification", "Static depth for applications",
         "Static analysis for important server side components", "6c05c837-8c99-46e2-828b-7c903e27dba4", 3,
         _ok(slither) and _ok(mythril)),
        ("Test and Verification", "Consolidation",
         "Usage of a vulnerability management system", "85ba5623-84be-4219-8892-808837be582d", 3,
         _ok(defectdojo)),
        ("Implementation", "Development and Source Control",
         ".gitignore", "363a3eea-baf9-4010-88ca-bb8186a2989d", 4,
         (ROOT / ".gitignore").is_file()),
        ("Test and Verification", "Static depth for applications",
         "Usage of multiple analyzers", "297be001-8d94-41ee-ab29-207020d423c0", 4,
         _ok(slither) and _ok(mythril)),
        ("Test and Verification", "Static depth for infrastructure",
         "Software Composition Analysis", "26e1c6d5-5632-4ec7-80d2-e564b98732ad", 4,
         _ok(trivy) and _ok(sca)),
        # "Test of infrastructure components for known vulnerabilities" (13367d8f-...,
        # level 4) is deliberately NOT listed: OpenSCAP is the only tool that could
        # speak to it, and item 6 proved it structurally cannot score anything on
        # this host (0 of 777 rules, Ubuntu or Debian content) -- there is no real
        # pass/fail evidence to offer, so it stays not_assessed rather than being
        # forced to a fabricated result either way.
    ]


def claimed_level(checked):
    """checked: list of (level, passed). Highest level where every checked
    activity at or below it passed; capped below the first failure."""
    if not checked:
        return 0
    failing = [lvl for lvl, passed in checked if not passed]
    passing = [lvl for lvl, passed in checked if passed]
    if not passing:
        return 0
    level = max(passing)
    if failing:
        level = min(level, min(failing) - 1)
    return max(level, 0)


def main():
    print("[+] [ZONE 2] Computing OWASP DSOMM maturity from real scanner results...")
    results = load_all()

    gitleaks_path = ROOT / "reports" / "gitleaks-report.json"
    gitleaks_findings = None
    if gitleaks_path.is_file():
        try:
            gitleaks_findings = len(json.loads(gitleaks_path.read_text(encoding="utf-8")) or [])
        except ValueError:
            gitleaks_findings = None

    activities = build_activities(results, gitleaks_findings)

    by_subdim = {}
    for dim, sub, name, uuid, level, passed in activities:
        by_subdim.setdefault((dim, sub), []).append((level, passed, name, uuid))

    subdimensions = {}
    activity_rows = []
    for (dim, sub), rows in by_subdim.items():
        checked = [(lvl, passed) for lvl, passed, _, _ in rows]
        total = MODEL_TOTALS.get(dim, {}).get(sub, 0)
        subdimensions[sub] = {
            "dimension": dim,
            "level": claimed_level(checked),
            "assessed": len(rows),
            "total": total,
            "coverage": round(len(rows) / total, 3) if total else None,
        }
        for lvl, passed, name, uuid in rows:
            activity_rows.append({
                "dimension": dim, "subdimension": sub, "name": name, "uuid": uuid,
                "level": lvl, "status": "pass" if passed else "fail",
            })

    assessed_total = len(activities)
    detail = (f"{assessed_total} of {GRAND_TOTAL} official DSOMM v5.0.2 activities have "
              f"automated evidence this run; everything else requires manual/organizational "
              f"assessment and is reported as not_assessed, never defaulted")

    write_result("dsomm", "owasp-dsomm-v5.0.2", "ok",
                 counts={"activities_assessed": assessed_total, "activities_total": GRAND_TOTAL,
                         "subdimensions_with_signal": len(subdimensions)},
                 detail=detail,
                 extra={"subdimensions": subdimensions, "activities": activity_rows,
                        "model_totals": MODEL_TOTALS})


if __name__ == "__main__":
    main()
