#!/usr/bin/env python3
import os
import sys
import requests
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(PROJECT_ROOT, "config", ".defectdojo.env")

if os.path.isfile(ENV_FILE):
    with open(ENV_FILE, "r") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                os.environ.setdefault(k, v.strip('"\''))

DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://127.0.0.1:8085")
DEFECTDOJO_TOKEN = os.getenv("DEFECTDOJO_TOKEN", "1c2ce9ac8c065cb29ced06912968af7ee32f7c68")

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

        upload_scan(eng_id, "Gitleaks Scan", os.path.join(PROJECT_ROOT, "reports/gitleaks-report.json"))
        upload_scan(eng_id, "Trivy Scan", "/tmp/trivy-report.json")
        
        zap_xml = os.path.join(PROJECT_ROOT, "reports/zap-dast-report.xml")
        zap_json = os.path.join(PROJECT_ROOT, "reports/dast/zap-report.json")
        if not upload_scan(eng_id, "ZAP Scan", zap_xml):
            upload_scan(eng_id, "ZAP Scan", zap_json)

        print("[+] [DEFECTDOJO] Ingestion cycle completed successfully.")
    except Exception as exc:
        print(f"[-] [DEFECTDOJO] Error communicating with DefectDojo: {exc}")

if __name__ == "__main__":
    main()
