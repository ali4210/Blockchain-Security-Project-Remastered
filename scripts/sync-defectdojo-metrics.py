#!/usr/bin/env python3
import os
import json
import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS_FILE = os.path.join(PROJECT_ROOT, "reports", "status.json")
URL = "http://127.0.0.1:8085/api/v2"
TOKEN = "1c2ce9ac8c065cb29ced06912968af7ee32f7c68"
HEADERS = {"Authorization": f"Token {TOKEN}"}

def fetch_metrics():
    try:
        all_res = requests.get(f"{URL}/findings/?limit=1", headers=HEADERS, timeout=5).json()
        active_res = requests.get(f"{URL}/findings/?active=true&duplicate=false&limit=500", headers=HEADERS, timeout=5).json()
        
        total_raw = all_res.get("count", 0)
        total_unique = active_res.get("count", 0)
        
        severities = {}
        for f in active_res.get("results", []):
            sev = f.get("severity", "Info")
            severities[sev] = severities.get(sev, 0) + 1
            
        dojo_metrics = {
            "status": "HEALTHY",
            "dashboard_url": "http://127.0.0.1:8085",
            "total_raw_findings": total_raw,
            "active_unique_findings": total_unique,
            "severity_breakdown": severities
        }
        
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, "r") as fp:
                data = json.load(fp)
            data["defectdojo_compliance"] = dojo_metrics
            with open(STATUS_FILE, "w") as fp:
                json.dump(data, fp, indent=2)
            print(f"[+] [DEFECTDOJO] Synced live compliance metrics to reports/status.json: {total_unique} active unique findings.")
        else:
            print("[*] [DEFECTDOJO] reports/status.json not found yet; skipping JSON update.")
    except Exception as exc:
        print(f"[*] [DEFECTDOJO] Metric sync note: {exc}")

if __name__ == "__main__":
    fetch_metrics()
