#!/usr/bin/env python3
"""Zone 2 SAST + symbolic analysis: real Slither and real Mythril only.

Nothing is ever invented: a missing or failing tool is recorded as not_run / error.
Canary: both VulnerableVault and SecureVault are scanned (SOC_CANARY=0 disables).
  * VulnerableVault MUST trigger Slither's reentrancy-eth (proves the detector works)
  * SecureVault MUST NOT trigger it (proves no false positive)
Mythril analyses solc runtime bytecode, so it needs no network and no solc download.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, RAW, write_result  # noqa: E402

SOLC_VERSION = os.getenv("SOLC_VERSION", "0.8.24")
MYTH_TIMEOUT = int(os.getenv("MYTHRIL_TIMEOUT", "60"))
VULN, SECURE = "VulnerableVault", "SecureVault"
DEFAULT_TARGET = f"contracts/solidity/{VULN}.sol"

SC01 = "SC01: Reentrancy Exploitation"
SC02 = "SC02: Access Control Vulnerability"
SC03 = "SC03: Unprotected Upgrade / Delegatecall"
SC10 = "SC10: General Logic / Compiler Flaw"
OWASP = {"reentrancy-eth": SC01, "reentrancy-no-eth": SC01,
         "arbitrary-send-eth": SC02, "suicidal": SC02,
         "unprotected-upgrade": SC03, "controlled-delegatecall": SC03}
SWC = {"SWC-107": SC01, "SWC-105": SC02, "SWC-106": SC02, "SWC-112": SC03}
RANK = {"ok": 0, "not_run": 1, "error": 2}


def _res(status, detail, findings=None, **kw):
    return {"status": status, "detail": detail, "findings": findings or [], **kw}


def slither_scan(target, tag):
    exe = shutil.which("slither") or str(Path.home() / ".local/bin/slither")
    if not Path(exe).exists():
        return _res("not_run", "slither is not installed")
    RAW.mkdir(parents=True, exist_ok=True)
    jpath, spath = RAW / f"slither-{tag}.json", RAW / f"slither-{tag}.sarif"
    for p in (jpath, spath):
        p.unlink(missing_ok=True)
    cmd = [exe, str(target), "--solc-solcs-select", SOLC_VERSION,
           "--json", str(jpath), "--sarif", str(spath)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240, cwd=ROOT)
    except Exception as exc:
        return _res("error", f"slither could not run: {exc}")
    if not jpath.is_file():
        return _res("error", f"slither produced no JSON; stderr tail: {proc.stderr.strip()[-300:]}")
    try:
        data = json.loads(jpath.read_text(encoding="utf-8"))
    except ValueError as exc:
        return _res("error", f"slither JSON unreadable: {exc}")
    if not data.get("success"):
        return _res("error", f"slither reported failure: {str(data.get('error'))[:200]}")
    findings = []
    for d in (data.get("results") or {}).get("detectors", []):
        check = d.get("check", "unknown")
        findings.append({
            "engine": "Slither", "check": check,
            "impact": str(d.get("impact", "Medium")).upper(),
            "confidence": d.get("confidence", "Medium"),
            "description": (d.get("description") or "").strip().split("\n")[0],
            "owasp_category": OWASP.get(check, SC10), "target": str(target)})
    return _res("ok", None, findings, sarif=spath if spath.is_file() else None)


def _myth_backend():
    exe = shutil.which("myth")
    local = Path.home() / ".local/bin/myth"
    if not exe and local.exists():
        exe = str(local)
    if exe:
        return "native", exe
    if shutil.which("docker"):
        probe = subprocess.run(["docker", "image", "inspect", "mythril/myth"], capture_output=True)
        if probe.returncode == 0:
            return "docker", None
    return None, None


def mythril_scan(target, tag):
    solc = shutil.which("solc")
    if not solc:
        return _res("not_run", "solc not on PATH (needed to build runtime bytecode)")
    mode, myth = _myth_backend()
    if not mode:
        return _res("not_run", "no `myth` binary and no local mythril/myth image (pipx install mythril, or docker pull mythril/myth)")
    findings, issues_raw = [], []
    with tempfile.TemporaryDirectory(prefix="myth-") as tmp:
        os.chmod(tmp, 0o755)
        try:
            comp = subprocess.run([solc, "--bin-runtime", "--overwrite", "-o", tmp, str(target)],
                                  capture_output=True, text=True, timeout=120, cwd=ROOT)
        except Exception as exc:
            return _res("error", f"solc failed to run: {exc}")
        bins = [p for p in sorted(Path(tmp).glob("*.bin-runtime")) if p.stat().st_size > 0]
        if comp.returncode != 0 or not bins:
            return _res("error", f"solc produced no runtime bytecode: {comp.stderr.strip()[-300:]}")
        for b in [p for p in bins if p.stem == Path(target).stem] or bins:
            os.chmod(b, 0o644)
            tail = ["analyze", "-f", None, "--bin-runtime", "-t", "3",
                    "--execution-timeout", str(MYTH_TIMEOUT), "--solver-timeout", "10000", "-o", "json"]
            if mode == "native":
                tail[2] = str(b)
                cmd = [myth] + tail
            else:
                tail[2] = f"/w/{b.name}"
                cmd = ["docker", "run", "--rm", "--network", "none",
                       "-v", f"{tmp}:/w:ro", "mythril/myth"] + tail
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=MYTH_TIMEOUT + 90)
                out = json.loads(proc.stdout)
            except subprocess.TimeoutExpired:
                return _res("error", "mythril exceeded its wall-clock limit")
            except ValueError:
                return _res("error", f"mythril output unparseable: {(proc.stdout or proc.stderr)[-200:]}")
            except Exception as exc:
                return _res("error", f"mythril could not run: {exc}")
            if not out.get("success", False):
                return _res("error", f"mythril reported failure: {str(out.get('error'))[:200]}")
            for issue in out.get("issues", []):
                swc = str(issue.get("swc-id", ""))
                swc = swc if swc.startswith("SWC-") else f"SWC-{swc}"
                issues_raw.append(issue)
                findings.append({
                    "engine": "Mythril", "check": issue.get("title", "Symbolic finding"),
                    "impact": str(issue.get("severity", "Medium")).upper(), "confidence": "High",
                    "description": (issue.get("description") or "").strip().split("\n")[0],
                    "owasp_category": SWC.get(swc, SC10), "swc": swc, "target": str(target)})
    raw = RAW / f"mythril-{tag}.json"
    raw.write_text(json.dumps({"issues": issues_raw}, indent=2), encoding="utf-8")
    return _res("ok", None, findings, raw=raw)


def pick_targets():
    primary = Path(os.getenv("TARGET_CONTRACT", DEFAULT_TARGET))
    primary = primary if primary.is_absolute() else ROOT / primary
    targets = [primary]
    if os.getenv("SOC_CANARY", "1") != "0" and primary.stem in (VULN, SECURE):
        other = primary.with_name(f"{SECURE if primary.stem == VULN else VULN}.sol")
        if other.is_file():
            targets.append(other)
    return targets


def count_by_impact(findings):
    out = {}
    for f in findings:
        k = f["impact"].lower()
        out[k] = out.get(k, 0) + 1
    return out


def worst(per, tool):
    return max((per[t][tool]["status"] for t in per), key=lambda s: RANK[s])


def main():
    strict = "--strict" in sys.argv
    targets = pick_targets()
    primary = targets[0]
    print(f"[+] [ZONE 2] Slither + Mythril on: {', '.join(t.name for t in targets)}")
    if not primary.is_file():
        for n in ("slither", "mythril", "sast-canary"):
            write_result(n, n, "error", detail=f"target not found: {primary}")
        sys.exit(2 if strict else 0)

    per = {t.stem: {"slither": slither_scan(t, t.stem), "mythril": mythril_scan(t, t.stem)}
           for t in targets}
    p = per[primary.stem]

    for tool in ("slither", "mythril"):
        bad = [f"{t}: {per[t][tool]['detail']}" for t in per if per[t][tool]["status"] != "ok"]
        raw = p[tool].get("sarif") if tool == "slither" else p[tool].get("raw")
        write_result(tool, tool, worst(per, tool), target=str(primary.relative_to(ROOT)),
                     counts=count_by_impact(p[tool]["findings"]) if p[tool]["status"] == "ok" else {},
                     raw_report=raw, detail="; ".join(bad) or None,
                     extra={"primary_target": primary.name})

    problems, relevant = [], False
    for t in targets:
        if t.stem not in (VULN, SECURE):
            continue
        relevant = True
        sl = per[t.stem]["slither"]
        if sl["status"] != "ok":
            problems.append(f"{t.stem}: slither {sl['status']}")
            continue
        hit = any(f["check"] == "reentrancy-eth" for f in sl["findings"])
        if t.stem == VULN and not hit:
            problems.append("VulnerableVault: Slither MISSED reentrancy-eth (detector broken)")
        if t.stem == SECURE and hit:
            problems.append("SecureVault: Slither reports reentrancy-eth (false positive)")
    if not relevant:
        write_result("sast-canary", "canary", "ok", detail="not applicable to this target")
    elif problems:
        write_result("sast-canary", "canary", "error", detail="; ".join(problems))
    else:
        write_result("sast-canary", "canary", "ok",
                     detail="vulnerable contract detected, secure contract clean"
                     if len(targets) == 2 else "single-target check passed")

    allf = p["slither"]["findings"] + p["mythril"]["findings"]
    summary = {}
    for f in allf:
        summary[f["owasp_category"]] = summary.get(f["owasp_category"], 0) + 1
    report = {"target": str(primary.relative_to(ROOT)), "totalFindings": len(allf),
              "findings": allf, "owaspSummary": summary,
              "toolStatus": {"slither": p["slither"]["status"], "mythril": p["mythril"]["status"]}}
    out_json = ROOT / "reports" / "sast-symbolic-report.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    sarif_out = ROOT / "reports" / "sast-symbolic-report.sarif"
    sarif_out.unlink(missing_ok=True)  # never leave a stale SARIF for DefectDojo
    if p["slither"].get("sarif"):
        shutil.copyfile(p["slither"]["sarif"], sarif_out)  # Slither's own SARIF, real line numbers
    for f in allf[:5]:
        print(f"       * [{f['engine']}] {f['check']} -> {f['owasp_category']}")
    if strict and any(per[t][k]["status"] != "ok" for t in per for k in ("slither", "mythril")):
        sys.exit(2)


if __name__ == "__main__":
    main()
