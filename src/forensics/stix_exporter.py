import os
import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any, List

class Stix21BundleExporter:
    """Exports forensic and threat intelligence findings into OASIS STIX 2.1 JSON bundles."""

    def __init__(self, output_dir: str = "reports/stix"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def create_incident_bundle(
        self,
        incident_id: str,
        target_contract: str,
        vulnerability_title: str,
        dread_score: float,
        evidence_sha256: str,
        attacker_or_flagged_address: str = "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b"
    ) -> Path:
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        bundle_id = f"bundle--{uuid.uuid4()}"

        # 1. Identity Object (Autonomous Blockchain SOC)
        identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'soc.autonomous.blockchain')}"
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "Autonomous Blockchain SOC Relayer Engine",
            "identity_class": "system"
        }

        # 2. Attack Pattern Object (e.g. Reentrancy Exploitation)
        attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"
        attack_pattern = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": attack_pattern_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Smart Contract Vulnerability: {vulnerability_title}",
            "description": f"Automated detection of {vulnerability_title} with DREAD risk score {dread_score} against {target_contract}",
            "external_references": [
                {
                    "source_name": "OWASP Smart Contract Top 10",
                    "external_id": "SC01"
                }
            ]
        }

        # 3. Indicator Object (Malicious Target or Interacting Address)
        indicator_id = f"indicator--{uuid.uuid4()}"
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Exploited Contract or Sanctioned Entity ({attacker_or_flagged_address[:10]}...)",
            "pattern_type": "stix",
            "pattern": f"[ethereum-address:value = '{attacker_or_flagged_address}']",
            "valid_from": now_iso,
            "labels": ["malicious-activity", "smart-contract-exploit", "tornado-cash-sdn"]
        }

        # 4. Observed Data Object (Sealed Evidence Hash)
        observed_id = f"observed-data--{uuid.uuid4()}"
        observed_data = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": now_iso,
            "modified": now_iso,
            "first_observed": now_iso,
            "last_observed": now_iso,
            "number_observed": 1,
            "objects": {
                "0": {
                    "type": "file",
                    "hashes": {
                        "SHA-256": evidence_sha256
                    },
                    "name": f"{incident_id}-sealed-evidence.log"
                }
            }
        }

        # 5. Relationship (Indicator indicates Attack Pattern)
        rel_id = f"relationship--{uuid.uuid4()}"
        relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": attack_pattern_id
        }

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": [identity, attack_pattern, indicator, observed_data, relationship]
        }

        output_file = self.output_dir / "latest-incident-stix.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)

        return output_file

if __name__ == "__main__":
    exporter = Stix21BundleExporter()
    out = exporter.create_incident_bundle(
        incident_id="INC-2026-001",
        target_contract="VulnerableVault",
        vulnerability_title="ReentrancyExternalCall",
        dread_score=8.5,
        evidence_sha256="a9e59db1a4766a98f480396440266e74b30df452140bb0686da217a99859f7df"
    )
    print(f"[+] STIX 2.1 Incident Bundle generated: {out}")
