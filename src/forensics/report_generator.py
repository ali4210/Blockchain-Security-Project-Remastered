"""
TODO(phase-10e): Forensic report generator.
Fills docs/forensic-report-template.md (13 sections, see blueprint 4.10)
from sealed evidence, timeline, attack-path graph, and the custody log.
Exports IOCs as a STIX 2.1 bundle. Status becomes "final" only after a
human analyst sign-off. Release only via the Zone 4 HITL egress gateway.
"""


def generate_report(_case_id: str) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10e")


def export_stix_bundle(_case_id: str) -> dict:
    raise NotImplementedError("not implemented — see checklist Phase 10e")
