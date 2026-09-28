# TODO(phase-10a): prove the custody log is append-only and hash-chained.
# - UPDATE/DELETE on custody_log must raise (trigger enforcement).
# - Editing one row must break verify_chain().
import pytest


def test_custody_log_is_append_only():
    pytest.skip("not implemented — see checklist Phase 10a")


def test_edited_entry_breaks_chain():
    pytest.skip("not implemented — see checklist Phase 10a")
