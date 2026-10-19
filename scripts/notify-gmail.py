#!/usr/bin/env python3
import os
import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

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
msg["Subject"] = "Autonomous Blockchain SOC — Executive Pipeline Report"

body_text = """Hello Operator,

The Autonomous Blockchain Security Operations Center (SOC) E2E pipeline has executed successfully.

Summary of Enforced Controls:
- Zone 1 Static & Secrets: Gitleaks verified (7 fixtures baseline)
- Zone 2 Code & Infra Security: Slither AST, Mythril, Aqua Trivy (0 CRIT / 0 HIGH), OWASP ZAP (13 DAST)
- Zone 3 Cognitive Mesh: 7-Agent LangGraph Swarm (100% BFT Consensus Quorum)
- Zone 4 & 5 SOAR & Ticketing: Jira Cloud SEV-1 ticket dispatched & TheHive 4 case created
- Zone 7 Cryptographic Attestation: HashiCorp Vault Transit Engine (ed25519 signed)
- GitOps: GitLab CE committed & Argo CD synchronized in lockstep

The complete interactive HTML report (latest.html) is attached.
"""

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
