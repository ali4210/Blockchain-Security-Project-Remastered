#!/usr/bin/env python3
"""Zone 2 SCA: run the project's own OSV/NVD lookup (run-sca.cjs) and record a real result.
SOC_SCA_MODE=inventory skips the network lookup and records not_run (an inventory is not a scan)."""
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, RAW, write_result  # noqa: E402


def main():
    print("[+] [ZONE 2] Running SCA dependency vulnerability lookup (OSV + NVD)...")
    if os.getenv("SOC_SCA_MODE") == "inventory":
        subprocess.run(["bash", "scripts/run-sca.sh", "--inventory"], cwd=ROOT, capture_output=True)
        return write_result("sca", "osv+nvd", "not_run",
                            detail="inventory only (SOC_SCA_MODE=inventory); no vulnerability lookup")
    try:
        proc = subprocess.run(["bash", "scripts/run-sca.sh", "--lookup-approved-public-dependencies"],
                              cwd=ROOT, capture_output=True, text=True, timeout=1500)
    except Exception as exc:
        return write_result("sca", "osv+nvd", "error", detail=f"lookup could not run: {exc}")
    try:
        s = json.loads(proc.stdout)
    except ValueError:
        s = None
    if proc.returncode != 0 or not s or s.get("status") != "lookup-completed":
        return write_result("sca", "osv+nvd", "error",
                            detail=(proc.stderr.strip()[-300:] or "lookup did not complete") +
                                   " (stale lock? ~/.local/state/blockchain-soc/p03-002/lookup.lock)")
    RAW.mkdir(parents=True, exist_ok=True)
    raw = RAW / "sca-summary.json"
    raw.write_text(json.dumps(s, indent=2), encoding="utf-8")
    counts = {"activeAdvisories": s.get("activeAdvisories", 0), "uniqueAdvisories": s.get("uniqueAdvisories", 0),
              "matchedPackages": s.get("matchedPackageCoordinates", 0)}
    npm = subprocess.run(["npm", "audit", "--json"], cwd=ROOT, capture_output=True, text=True)
    try:
        v = json.loads(npm.stdout).get("metadata", {}).get("vulnerabilities", {})
        counts["npmAuditHigh"], counts["npmAuditCritical"] = v.get("high", 0), v.get("critical", 0)
    except ValueError:
        pass
    write_result("sca", "osv+nvd", "ok", counts=counts, raw_report=raw,
                 detail="inventory + OSV lookup; securityAcceptance stays 'not-established' by design",
                 extra={"evidenceDirectory": s.get("evidenceDirectory")})


if __name__ == "__main__":
    main()
