# TODO(phase-10a): prove tamper detection.
# - Hash a file, flip one byte, confirm verify_manifest() fails.
# - Confirm build_manifest()/sign_manifest() round-trip verifies clean.
import pytest


def test_tamper_is_detected():
    pytest.skip("not implemented — see checklist Phase 10a")
