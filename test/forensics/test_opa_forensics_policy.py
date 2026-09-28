# TODO(phase-10b): prove least-privilege on the forensics policy.
# - "agent" principal: allowed forensics.list_evidence, denied forensics.acquire
# - "soc-operator" principal: allowed forensics.acquire
# - nobody: forensics.modify_original / delete_original always denied
import pytest


def test_agent_is_read_only():
    pytest.skip("not implemented — see checklist Phase 10b")


def test_operator_can_acquire():
    pytest.skip("not implemented — see checklist Phase 10b")


def test_modify_original_always_denied():
    pytest.skip("not implemented — see checklist Phase 10b")
