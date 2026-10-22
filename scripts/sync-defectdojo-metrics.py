#!/usr/bin/env python3
import os
import json
import time
import requests

REQUEST_TIMEOUT = 15  # DefectDojo answered a direct test in 1.4s; 5s was too tight under load
RETRIES = 3
BACKOFF_BASE = 1.5  # seconds; attempt N waits BACKOFF_BASE * N before retrying


def get_with_retry(url, headers, label, timeout=REQUEST_TIMEOUT, retries=RETRIES):
    """GET with retry/backoff. Returns the Response on success, or None after all
    retries are exhausted -- never raises, so one flaky call can't take down the
    others. Prints a clear warning per failed attempt so operators can see in logs
    which specific metric didn't refresh, even though the caller swallows this."""
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return requests.get(url, headers=headers, timeout=timeout)
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            print(f"[!] [DEFECTDOJO EXPORTER] {label}: attempt {attempt}/{retries} failed ({exc})")
            if attempt < retries:
                time.sleep(BACKOFF_BASE * attempt)
    print(f"[!] [DEFECTDOJO EXPORTER] {label}: giving up after {retries} attempts ({last_exc})")
    return None

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS_FILE = os.path.join(PROJECT_ROOT, "reports", "status.json")
PROM_FILE = os.path.join(PROJECT_ROOT, "reports", "metrics.prom")

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN")
URL = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8085") + "/api/v2"

# Token: env var first, else Vault secret/data/defectdojo (needs VAULT_TOKEN).
# Never hardcoded, never read from a tracked file.
TOKEN = os.environ.get("DEFECTDOJO_TOKEN")
if not TOKEN and VAULT_TOKEN:
    try:
        resp = requests.get(
            f"{VAULT_ADDR}/v1/secret/data/defectdojo",
            headers={"X-Vault-Token": VAULT_TOKEN}, timeout=5,
        )
        data = resp.json().get("data", {}).get("data", {})
        TOKEN = data.get("token")
        URL = data.get("url", URL.replace("/api/v2", "")) + "/api/v2"
    except Exception:
        TOKEN = None

if not TOKEN:
    print("[*] [DEFECTDOJO EXPORTER] No DEFECTDOJO_TOKEN (env or Vault secret/data/defectdojo); skipping")
    raise SystemExit(0)

HEADERS = {"Authorization": f"Token {TOKEN}"}


def fetch_defectdojo_counts():
    """Returns (ok, total_raw, total_unique, severities). Never raises -- a failed
    or flaky request here just means ok=False, so callers can still use whatever
    other metrics succeeded instead of losing everything."""
    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    all_resp = get_with_retry(f"{URL}/findings/?limit=1", HEADERS, "DefectDojo total findings count")
    active_resp = get_with_retry(f"{URL}/findings/?active=true&duplicate=false&limit=500", HEADERS,
                                  "DefectDojo active/unique findings")
    if all_resp is None or active_resp is None or all_resp.status_code != 200 or active_resp.status_code != 200:
        print("[!] [DEFECTDOJO EXPORTER] Could not refresh DefectDojo finding counts this run "
              "(see attempt warnings above); leaving status.json defectdojo_compliance untouched.")
        return False, 0, 0, severities
    try:
        all_res, active_res = all_resp.json(), active_resp.json()
    except ValueError as exc:
        print(f"[!] [DEFECTDOJO EXPORTER] DefectDojo returned unparseable JSON: {exc}")
        return False, 0, 0, severities
    total_raw = all_res.get("count", 0)
    total_unique = active_res.get("count", 0)
    for f in active_res.get("results", []):
        sev = f.get("severity", "Info")
        severities[sev] = severities.get(sev, 0) + 1
    return True, total_raw, total_unique, severities


def fetch_zap_alerts():
    """Returns (ok, alerts, source_text). Independent of the DefectDojo count
    query above and the TheHive query below -- a failure here must not block
    either of those."""
    zap_test_resp = get_with_retry(
        f"{URL}/tests/?engagement__name=SOC-Continuous-Compliance&test_type__name=ZAP+Scan",
        HEADERS, "ZAP test lookup")
    if zap_test_resp is None:
        return False, 0, "ZAP test lookup failed (see attempt warnings above)"
    if zap_test_resp.status_code != 200:
        print(f"[!] [DEFECTDOJO EXPORTER] ZAP test lookup returned HTTP {zap_test_resp.status_code}")
        return False, 0, f"ZAP test lookup returned HTTP {zap_test_resp.status_code}"
    try:
        zap_test_res = zap_test_resp.json()
    except ValueError as exc:
        print(f"[!] [DEFECTDOJO EXPORTER] ZAP test lookup returned unparseable JSON: {exc}")
        return False, 0, "ZAP test lookup returned unparseable JSON"
    if zap_test_res.get("count", 0) == 0:
        return False, 0, "no ZAP test found in DefectDojo"

    last_zap_id = zap_test_res["results"][-1]["id"]
    zap_alerts_resp = get_with_retry(f"{URL}/findings/?test={last_zap_id}", HEADERS,
                                      f"ZAP alerts for test id {last_zap_id}")
    if zap_alerts_resp is None or zap_alerts_resp.status_code != 200:
        print(f"[!] [DEFECTDOJO EXPORTER] Could not fetch ZAP alerts for test id {last_zap_id}")
        return False, 0, f"found ZAP test id {last_zap_id} but could not fetch its alerts"
    try:
        zap_alerts = zap_alerts_resp.json().get("count", 0)
    except ValueError as exc:
        print(f"[!] [DEFECTDOJO EXPORTER] ZAP alerts response unparseable: {exc}")
        return False, 0, f"found ZAP test id {last_zap_id} but its alerts response was unparseable"
    return True, zap_alerts, f"queried from DefectDojo test id {last_zap_id}"


def fetch_thehive_cases():
    """Returns (cases_or_none, status_text). Independent of the DefectDojo/ZAP
    queries above -- a TheHive outage must not drop the DefectDojo counts that
    already succeeded."""
    thehive_url = os.environ.get("THEHIVE_URL", "http://127.0.0.1:9005")
    thehive_token = os.environ.get("THEHIVE_TOKEN")
    if not thehive_token:
        return None, "UNKNOWN (no THEHIVE_TOKEN)"
    last_exc = None
    for attempt in range(1, RETRIES + 1):
        try:
            th_res = requests.post(
                f"{thehive_url}/api/v1/query",
                headers={"Authorization": f"Bearer {thehive_token}"},
                json={"query": [{"_name": "listCase"}, {"_name": "count"}]},
                timeout=REQUEST_TIMEOUT,
            ).json()
            cases = th_res if isinstance(th_res, int) else th_res.get("count")
            return cases, "HEALTHY (Active)" if cases is not None else "UNKNOWN (query returned no count)"
        except (requests.exceptions.RequestException, ValueError) as exc:
            last_exc = exc
            print(f"[!] [DEFECTDOJO EXPORTER] TheHive case count: attempt {attempt}/{RETRIES} failed ({exc})")
            if attempt < RETRIES:
                time.sleep(BACKOFF_BASE * attempt)
    print(f"[!] [DEFECTDOJO EXPORTER] TheHive case count: giving up after {RETRIES} attempts ({last_exc})")
    return None, "UNKNOWN (query failed)"


def fetch_metrics():
    defectdojo_ok, total_raw, total_unique, severities = fetch_defectdojo_counts()
    zap_ok, zap_alerts, zap_source = fetch_zap_alerts()
    thehive_cases, thehive_status_text = fetch_thehive_cases()
    thehive_cases_line = thehive_cases if thehive_cases is not None else 0
    thehive_url = os.environ.get("THEHIVE_URL", "http://127.0.0.1:9005")

    try:
        # Update status.json -- only touch defectdojo_compliance if the core
        # DefectDojo counts actually refreshed this run. Partial data (DefectDojo
        # ok, ZAP/TheHive not) still beats no data, so this never depends on the
        # ZAP or TheHive lookups succeeding.
        if defectdojo_ok and os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, "r") as fp:
                data = json.load(fp)
            data["defectdojo_compliance"] = {
                "status": "HEALTHY",
                "dashboard_url": URL.replace("/api/v2", ""),
                "total_raw_findings": total_raw,
                "active_unique_findings": total_unique,
                "severity_breakdown": severities,
                "zap_alerts_source": zap_source,
            }
            with open(STATUS_FILE, "w") as fp:
                json.dump(data, fp, indent=2)
            print(f"[+] [DEFECTDOJO EXPORTER] Updated status.json defectdojo_compliance "
                  f"({total_unique} active unique findings)")
    except (OSError, ValueError) as exc:
        print(f"[!] [DEFECTDOJO EXPORTER] Could not update status.json: {exc}")

    try:
        # Append to Prometheus metrics.prom for Grafana Port 3000 -- written
        # regardless of which parts above succeeded, same as before.
        prom_lines = [
            "\n# HELP defectdojo_active_unique_findings Number of active deduplicated findings in DefectDojo",
            "# TYPE defectdojo_active_unique_findings gauge",
            f"defectdojo_active_unique_findings {total_unique}",
            "# HELP defectdojo_raw_total_findings Total raw findings uploaded to DefectDojo",
            "# TYPE defectdojo_raw_total_findings gauge",
            f"defectdojo_raw_total_findings {total_raw}",
            "# HELP defectdojo_findings_by_severity Active findings grouped by severity",
            "# TYPE defectdojo_findings_by_severity gauge",
            f'defectdojo_findings_by_severity{{severity="Critical"}} {severities.get("Critical", 0)}',
            f'defectdojo_findings_by_severity{{severity="High"}} {severities.get("High", 0)}',
            f'defectdojo_findings_by_severity{{severity="Medium"}} {severities.get("Medium", 0)}',
            f'defectdojo_findings_by_severity{{severity="Low"}} {severities.get("Low", 0)}',
            "# HELP zap_dast_alerts_total Total DAST alerts cataloged from OWASP ZAP",
            "# TYPE zap_dast_alerts_total gauge",
            f"zap_dast_alerts_total {zap_alerts}",
            "# HELP thehive_cases_total Total forensic incident cases managed in TheHive",
            "# TYPE thehive_cases_total gauge",
            f"thehive_cases_total {thehive_cases_line}",
            f'blockchain_soc_tool_status{{tool="DefectDojo Compliance",endpoint="{URL.replace("/api/v2", "")}",artifact="Continuous AppSec Hub & Ingestion Engine",status_text="{"HEALTHY (Active)" if defectdojo_ok else "UNREACHABLE / QUERY FAILED"}"}} {1 if defectdojo_ok else 0}',
            f'blockchain_soc_tool_status{{tool="TheHive 4 SIEM",endpoint="{thehive_url}",artifact="Incident Response & Case Management",status_text="{thehive_status_text}"}} {1 if thehive_cases is not None else 0}',
            f'blockchain_soc_tool_status{{tool="OWASP ZAP DAST",endpoint="Containerized (Host Net)",artifact="Dynamic Baseline AppSec Scan",status_text="{zap_source}"}} {1 if zap_ok else 0}\n'
        ]

        if os.path.exists(PROM_FILE):
            with open(PROM_FILE, "a") as pf:
                pf.write("\n".join(prom_lines))
            print(f"[+] [PROMETHEUS] Exported DefectDojo ({total_unique} flaws), ZAP DAST ({zap_alerts} alerts, {zap_source}), and TheHive ({thehive_cases_line} cases) to {PROM_FILE}")
    except OSError as exc:
        print(f"[!] [DEFECTDOJO EXPORTER] Could not write {PROM_FILE}: {exc}")


if __name__ == "__main__":
    fetch_metrics()