#!/usr/bin/env python3
import os
import sys
import requests
import json
from datetime import datetime, timezone

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
        skipped = [n for n in ("trivy", "zap", "slither") if n not in results]
        failed = [n for n, ok in results.items() if not ok]
        if skipped:
            print(f"[!] [DEFECTDOJO] Skipped (scanner did not run ok this run): {', '.join(skipped)}")
        if failed:
            print(f"[-] [DEFECTDOJO] Upload FAILED for: {', '.join(failed)}")
            sys.exit(1)
        print("[+] [DEFECTDOJO] Ingestion cycle finished (see skipped/failed lines above).")
    except Exception as exc:
        print(f"[-] [DEFECTDOJO] Error communicating with DefectDojo: {exc}")

if __name__ == "__main__":
    main()
