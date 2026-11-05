#!/usr/bin/env python3
"""Real Lynis host-compliance audit, wired into the live pipeline.

Runs the same proven non-root, no-plugins command already validated once
manually (docs/CHECKLIST.md P03-008), then normalizes it through the
existing governance-core.cjs validator via run-governance.cjs. Purely
additive/informational -- NOT in pipeline-verdict.py's REQUIRED list, and it
can never affect PASS/HALT. Honest-failure pattern: every exit path writes a
real status (ok/not_run/error), never silently swallowed.

This script measures the LIVE binary/profile/package state and feeds it to
governance-core.cjs's own strict validator -- it does not assume today's
pinned config/governance-policy.json values still match. If Lynis is ever
upgraded, the validator will correctly reject the report as drifted,
reported here as status=error, not silently passed.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, RAW, write_result  # noqa: E402

PROFILE = Path("/etc/lynis/default.prf")
REPORT_PATH = RAW / "lynis-report.dat"
LOG_PATH = RAW / "lynis.log"
METADATA_PATH = RAW / "lynis-metadata.json"
GOVERNANCE_OUTPUT = ROOT / "reports" / "lynis-governance-report.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    print("[+] [ZONE 2] Running Lynis host-compliance audit...")

    lynis = shutil.which("lynis")
    if not lynis:
        return write_result("lynis", "lynis", "not_run", detail="lynis binary not installed")
    if not PROFILE.is_file():
        return write_result("lynis", "lynis", "not_run", detail=f"{PROFILE} not found")
    if os.geteuid() == 0:
        return write_result("lynis", "lynis", "not_run",
                             detail="refusing to run as root -- this audit is non-root by design")

    RAW.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.unlink(missing_ok=True)
    LOG_PATH.unlink(missing_ok=True)

    cmd = [lynis, "audit", "system", "--quick", "--no-colors", "--no-plugins",
           "--profile", str(PROFILE), "--report-file", str(REPORT_PATH),
           "--log-file", str(LOG_PATH)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc = None
        timed_out = True

    if timed_out or proc is None:
        return write_result("lynis", "lynis", "error", detail="lynis timed out after 300s")
    if proc.returncode != 0 or not REPORT_PATH.is_file():
        return write_result("lynis", "lynis", "error",
                             detail=f"lynis exit {proc.returncode}: {proc.stderr.strip()[-250:]}")

    version_out = subprocess.run([lynis, "--version"], capture_output=True, text=True).stdout.strip()
    pkg_out = subprocess.run(["dpkg-query", "-W", "-f=${Version}", "lynis"],
                              capture_output=True, text=True).stdout.strip()
    try:
        baseline = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                   capture_output=True, text=True, check=True).stdout.strip()
    except subprocess.CalledProcessError:
        return write_result("lynis", "lynis", "error", detail="could not resolve git HEAD for provenance")

    metadata = {
        "provider": "Lynis",
        "programVersion": version_out,
        "packageVersion": pkg_out,
        "providerExecutableSha256": sha256_file(Path(lynis)),
        "profileSha256": sha256_file(PROFILE),
        "reportSha256": sha256_file(REPORT_PATH),
        "exitCode": proc.returncode,
        "timedOut": False,
        "nonRoot": True,
        "effectiveUid": os.geteuid(),
        "pluginsDisabled": True,
        "uploadOptionUsed": False,
        "remoteAuditOptionUsed": False,
        "assessmentExecutedSuccessfully": True,
        "repositoryBaseline": baseline,
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    gov = subprocess.run(
        ["node", str(ROOT / "scripts" / "run-governance.cjs"),
         "--report", str(REPORT_PATH), "--metadata", str(METADATA_PATH)],
        capture_output=True, text=True,
    )
    if gov.returncode != 0:
        return write_result("lynis", "lynis", "error",
                             detail=f"governance-core.cjs rejected this run's report/metadata "
                                    f"(binary/profile/version drift from the pinned policy, or "
                                    f"malformed report): {gov.stderr.strip()[-250:]}")
    try:
        normalized = json.loads(gov.stdout)
    except ValueError:
        return write_result("lynis", "lynis", "error", detail="governance-core.cjs output unparseable")

    GOVERNANCE_OUTPUT.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    summary = normalized.get("summary", {})
    write_result(
        "lynis", "lynis", "ok", version=version_out, target="host",
        counts={"warnings": summary.get("warningRecords", 0),
                "suggestions": summary.get("suggestionRecords", 0),
                "tests_done": summary.get("providerTestsDone", 0),
                "hardening_index": normalized.get("providerMetric", {}).get("hardeningIndex")},
        raw_report=REPORT_PATH,
        detail=f"hardening_index={normalized.get('providerMetric', {}).get('hardeningIndex')}, "
               f"{summary.get('findingRecords', 0)} finding record(s) -- review-required, "
               f"no compliance/certification claim (see providerMetric.isNistCompliancePercentage=false)",
    )


if __name__ == "__main__":
    main()
