import os
import sys
from pathlib import Path

# Explicitly ensure repository root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.incident.safe_pause_builder import SafeEmergencyPauseBuilder
from src.incident.jira_dispatcher import JiraIncidentDispatcher
from src.forensics.stix_exporter import Stix21BundleExporter

def main():
    print("\n[+] [ZONE 4] Dispatching Jira SEV-1 Incident Ticket & Safe Pause Proposal...")
    
    # 1. Build Gnosis Safe Emergency Pause Calldata
    pause_builder = SafeEmergencyPauseBuilder()
    safe_tx = pause_builder.build_pause_calldata()
    print(f"    -> Gnosis Safe Pause Payload Built: to={safe_tx.get('to')} call={safe_tx.get('data')}")

    # 2. Export STIX 2.1 Threat Indicator Bundle (Zone 5)
    print("\n[+] [ZONE 5] Exporting OASIS STIX 2.1 Threat Indicator Bundle...")
    exporter = Stix21BundleExporter()
    stix_path = exporter.create_incident_bundle(
        incident_id="INC-CRIT-992",
        target_contract="VulnerableVault",
        vulnerability_title="ReentrancyExternalCall",
        dread_score=8.5,
        evidence_sha256="a9e59db1a4766a98f480396440266e74b30df452140bb0686da217a99859f7df"
    )
    print(f"    -> STIX 2.1 Threat Intelligence Bundle Sealed: {stix_path}")

    # 3. Dispatch Live Jira SEV-1 Ticket (Zone 4)
    dispatcher = JiraIncidentDispatcher()
    ticket = dispatcher.dispatch_sev1_ticket(
        incident_id="INC-CRIT-992",
        contract="VulnerableVault",
        vulnerability="ReentrancyExternalCall",
        dread_score=8.5,
        safe_tx_hash=safe_tx.get("safeTxHash", "0x0"),
        stix_bundle_path=str(stix_path)
    )
    print(f"    -> Jira SEV-1 Incident Action: Key={ticket.get('key')} Status={ticket.get('status')}")
    if ticket.get("url"):
        print(f"    -> Jira Ticket URL: {ticket.get('url')}")

if __name__ == "__main__":
    main()
