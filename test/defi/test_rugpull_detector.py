"""Real tests for src/defi/rugpull_detector.py, including Phase 4a's new
OWNABLE_INHERITANCE_RE recognition: a contract that inherits OpenZeppelin's
Ownable/Ownable2Step genuinely gets a real, callable renounceOwnership()
once deployed, even though the word "renounce" never appears in its own
file (that declaration lives in Ownable.sol's own, separate AST). Before
this phase, missing_ownership_protection would have stayed blind to that
real capability.

Finding-count regression guards use the REAL project fixtures
(VulnerableVault.sol untouched, SecureVault.sol migrated to OZ this
phase) compiled via real solc, not synthetic ASTs -- the strongest real
evidence that nothing regressed.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "defi"))
import rugpull_detector as rd  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
VULNERABLE_VAULT = ROOT / "contracts" / "solidity" / "VulnerableVault.sol"
SECURE_VAULT = ROOT / "contracts" / "solidity" / "SecureVault.sol"


# ---- isolated regex-logic unit tests (no compile needed) ------------------

def test_owner_modifier_re_matches_real_openzeppelin_modifier_name():
    assert rd.OWNER_MODIFIER_RE.search("onlyOwner")
    assert rd.OWNER_MODIFIER_RE.search("onlyowner")


def test_ownable_inheritance_re_matches_real_openzeppelin_names():
    assert rd.OWNABLE_INHERITANCE_RE.search("Ownable")
    assert rd.OWNABLE_INHERITANCE_RE.search("Ownable2Step")


def test_ownable_inheritance_re_does_not_match_unrelated_owner_word():
    """'owner' alone (a plain variable/parameter name) must not false-
    positive as if the contract inherited OpenZeppelin's Ownable -- those
    are two different, deliberately distinct regexes."""
    assert not rd.OWNABLE_INHERITANCE_RE.search("owner")
    assert not rd.OWNABLE_INHERITANCE_RE.search("newOwner")


def test_check_ownership_protection_passes_on_ownable_inheritance_alone():
    """Synthetic AST-text-level test: a privileged function plus the word
    'Ownable' (as it would appear via a real inheritance specifier) must
    pass, even with no literal 'renounce'/'timelock' text at all."""
    functions = [{"name": "adminOnly", "modifiers": [{"modifierName": {"name": "onlyOwner"}}],
                 "body": {}}]
    contract_text = "ProbeContract Ownable adminOnly onlyOwner"
    result = rd.check_ownership_protection(functions, contract_text)
    assert result["result"] == "pass"
    assert "renounce-ownership path" in result["justification"]


def test_check_ownership_protection_fails_without_ownable_or_renounce_or_timelock():
    functions = [{"name": "adminOnly", "modifiers": [{"modifierName": {"name": "onlyOwner"}}],
                 "body": {}}]
    contract_text = "ProbeContract adminOnly onlyOwner owner"
    result = rd.check_ownership_protection(functions, contract_text)
    assert result["result"] == "fail"


# ---- real finding-count regression guards (Phase 4a before/after) --------

def test_vulnerable_vault_real_finding_counts_unchanged():
    """VulnerableVault.sol was never touched this phase -- locks in the
    exact real checks verified before and after the Phase 4a migration."""
    checks = rd.analyze_contract(VULNERABLE_VAULT)
    results = {c["check"]: c["result"] for c in checks}
    assert results == {
        "unrestricted_mint": "pass",
        "missing_ownership_protection": "fail",
        "missing_liquidity_lock": "not_applicable",
        "owner_only_withdraw_all": "fail",
    }
    assert sum(1 for c in checks if c["result"] == "fail") == 2


def test_secure_vault_real_finding_counts_still_clean_after_oz_migration():
    """SecureVault.sol's owner pattern was migrated to OpenZeppelin's
    Ownable this phase -- must still be all pass/not_applicable, same as
    before migration, and the renounce-path must now be real OZ
    recognition specifically (not just the pre-existing timelock match)."""
    checks = rd.analyze_contract(SECURE_VAULT)
    results = {c["check"]: c["result"] for c in checks}
    assert results == {
        "unrestricted_mint": "pass",
        "missing_ownership_protection": "pass",
        "missing_liquidity_lock": "not_applicable",
        "owner_only_withdraw_all": "not_applicable",
    }
    assert sum(1 for c in checks if c["result"] == "fail") == 0

    ownership = next(c for c in checks if c["check"] == "missing_ownership_protection")
    assert "renounce-ownership path" in ownership["justification"]
