#!/usr/bin/env python3
"""Real OpenSCAP evaluation. Status comes from the results XML, never from a label.

Setup:  sudo apt install ssg-base ssg-debderived   (provides ssg-*-ds.xml)
Env:    OSCAP_DATASTREAM, OSCAP_PROFILE, OSCAP_SUDO=1 (run oscap via `sudo -n`)
Kali is not an official SSG target, so many rules may be notapplicable/notchecked;
that is reported, not hidden.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, RAW, write_result  # noqa: E402

DEFAULT_PROFILE = "xccdf_org.ssgproject.content_profile_standard"


def pick_datastream():
    env = os.getenv("OSCAP_DATASTREAM")
    if env:
        return Path(env) if Path(env).is_file() else None
    found = sorted(glob.glob("/usr/share/xml/scap/ssg/content/ssg-*-ds.xml"))
    for pref in ("debian13", "debian12", "debian11"):
        for f in found:
            if pref in f:
                return Path(f)
    return Path(found[0]) if found else None


def count_results(xml_path):
    counts = Counter()
    # NB: iter() does not support the {*} wildcard; findall() does
    for rr in ET.parse(xml_path).getroot().findall(".//{*}rule-result"):
        counts[(rr.findtext("{*}result") or "unknown").strip()] += 1
    return dict(counts)


def finish(status, detail, counts=None, ds=None, profile=None, raw=None, version=None):
    legacy = {"engine": "OpenSCAP", "binary_found": bool(shutil.which("oscap")),
              "datastream": str(ds) if ds else None, "profile": profile,
              "status": {"ok": "AUDITED_ACTIVE", "not_run": "NOT_RUN", "error": "ERROR"}[status],
              "compliance_standard": "SCAP Security Guide baseline (advisory; Kali is not an official target)",
              "counts": counts or {}}
    p = ROOT / "reports" / "openscap-report.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(legacy, indent=2), encoding="utf-8")
    write_result("openscap", "oscap", status, version=version, counts=counts,
                 raw_report=raw, detail=detail,
                 extra={"datastream": str(ds) if ds else None, "profile": profile})


def main():
    print("[+] [ZONE 2] Running OpenSCAP evaluation...")
    oscap = shutil.which("oscap")
    if not oscap:
        return finish("not_run", "oscap binary not installed")
    ver = (subprocess.run([oscap, "--version"], capture_output=True, text=True).stdout or "").splitlines()
    version = ver[0][:80] if ver else None
    ds = pick_datastream()
    if not ds:
        return finish("not_run", "no SCAP datastream found: sudo apt install ssg-base ssg-debderived", version=version)
    info = subprocess.run([oscap, "info", str(ds)], capture_output=True, text=True)
    profiles = re.findall(r"Id:\s+(xccdf_\S+)", info.stdout)
    profile = os.getenv("OSCAP_PROFILE", DEFAULT_PROFILE)
    if profile not in profiles:
        return finish("error", f"profile {profile} not in {ds.name}; available: {', '.join(profiles[:6]) or 'none parsed'}",
                      ds=ds, profile=profile, version=version)
    RAW.mkdir(parents=True, exist_ok=True)
    res_xml, rep_html = RAW / "oscap-results.xml", RAW / "oscap-report.html"
    res_xml.unlink(missing_ok=True)
    cmd = ["sudo", "-n"] if os.getenv("OSCAP_SUDO") == "1" else []
    cmd += [oscap, "xccdf", "eval", "--profile", profile, "--results", str(res_xml),
            "--report", str(rep_html), str(ds)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except Exception as exc:
        return finish("error", f"oscap could not run: {exc}", ds=ds, profile=profile, version=version)
    if proc.returncode not in (0, 2) or not res_xml.is_file():
        return finish("error", f"oscap exit {proc.returncode}: {proc.stderr.strip()[-250:]}",
                      ds=ds, profile=profile, version=version)
    try:
        counts = count_results(res_xml)
    except ET.ParseError as exc:
        return finish("error", f"results XML unreadable: {exc}", ds=ds, profile=profile, version=version)
    total = sum(counts.values())
    if total == 0:
        return finish("error", "results XML contains no rule results", ds=ds, profile=profile, version=version)
    scored = counts.get("pass", 0) + counts.get("fail", 0)
    detail = f"{ds.name}: {counts.get('pass', 0)}/{scored} scored rules pass"
    if counts.get("notapplicable", 0) > total / 2:
        detail += " (most rules notapplicable: platform mismatch)"
    finish("ok", detail, counts, ds, profile, res_xml, version)


if __name__ == "__main__":
    main()
