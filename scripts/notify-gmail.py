#!/usr/bin/env python3
import os
import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
from scanner_result import load_all

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML_REPORT = os.path.join(REPO_ROOT, "reports", "latest.html")

# Read credentials from .env
env = {}
env_path = os.path.join(REPO_ROOT, ".env")
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v.strip('"\'')

sender_email = env.get("GMAIL_SENDER")
app_password = env.get("GMAIL_APP_PASSWORD")
receiver_email = env.get("GMAIL_RECEIVER", sender_email)

if not (sender_email and app_password) or "your.email" in sender_email:
    print("[-] [GMAIL] Error: Valid GMAIL_SENDER or GMAIL_APP_PASSWORD not set in .env")
    sys.exit(1)

# Build email message
msg = MIMEMultipart()
msg["From"] = f"Blockchain SOC Orchestrator <{sender_email}>"
msg["To"] = receiver_email

_scan = load_all()
try:
    _v = json.load(open(os.path.join(REPO_ROOT, "reports", "verdict.json")))
except (OSError, ValueError):
    _v = {"health": "UNKNOWN", "verdict": "UNKNOWN", "halt_reasons": [], "health_problems": []}
_lines = []
for _n, _r in _scan.items():
    _c = ", ".join(f"{k}={v}" for k, v in (_r.get("counts") or {}).items())
    _lines.append(f"- {_n}: {_r.get('status', '?').upper()}" + (f" ({_c})" if _c else "") +
                  (f" - {(_r.get('detail') or '')[:100]}" if _r.get("status") != "ok" else ""))
body_text = (
    "Hello Operator,\n\n"
    f"Pipeline HEALTH: {_v['health']}   VERDICT: {_v['verdict']}\n"
    + "".join(f"  halt reason: {r}\n" for r in _v.get("halt_reasons", []))
    + "".join(f"  health problem: {p}\n" for p in _v.get("health_problems", []))
    + "\nScanner results (read from this run's evidence, not hardcoded):\n"
    + "\n".join(_lines)
    + "\n\nThe HTML report (latest.html) is attached.\n"
)
msg["Subject"] = "Blockchain SOC pipeline: " + ("HEALTH FAILED" if _v["health"] != "OK" else "verdict " + _v["verdict"])

msg.attach(MIMEText(body_text, "plain"))

# Attach reports/latest.html
if os.path.exists(HTML_REPORT):
    with open(HTML_REPORT, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment; filename=\"latest.html\"")
    msg.attach(part)
else:
    print(f"[-] [GMAIL] Warning: {HTML_REPORT} not found, sending without attachment.")

# Send via Gmail SMTP (SSL Port 465)
try:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, app_password)
        server.send_message(msg)
    print(f"[+] [NOTIFICATION] Full HTML report emailed to {receiver_email} successfully.")
except Exception as e:
    print(f"[-] [NOTIFICATION] Failed to send email: {e}")
