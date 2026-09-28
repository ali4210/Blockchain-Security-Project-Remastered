"""
TODO(phase-13): Continuous Address Risk Screening.
Schedules Zone 5's GraphSense/Web3.py fund-tracing integration to run
continuously (not just post-incident) against every counterparty address
a monitored contract interacts with, checked against a sanctions list
(e.g. a local OFAC snapshot) and known-risk address clusters.
"""


def screen_address(_address: str) -> dict:
    raise NotImplementedError("not implemented — see checklist Phase 13")


def run_continuous_screening(_contract_address: str) -> None:
    raise NotImplementedError("not implemented — see checklist Phase 13")
