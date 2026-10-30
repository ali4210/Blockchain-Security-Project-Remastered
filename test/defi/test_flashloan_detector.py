"""Real tests for src/defi/flashloan_detector.py, including a Phase 4a
regression test for a real bug found while preparing to migrate a contract
to OpenZeppelin: get_ast() silently returned the WRONG file's AST (an
imported dependency's, not the target's own) whenever the target had any
real import, because solc's combined-json output gains one `sources` entry
per resolved file and the old code blindly took the first one.

All compiles here are real `solc` invocations (no mocking an AST shape) --
the whole point is to prove the real compiler/detector interaction, not a
fabricated one.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "defi"))
import flashloan_detector as fd  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
VULNERABLE_VAULT = ROOT / "contracts" / "solidity" / "VulnerableVault.sol"
SECURE_VAULT = ROOT / "contracts" / "solidity" / "SecureVault.sol"


def test_get_ast_returns_the_targets_own_ast_for_a_plain_contract():
    ast = fd.get_ast(VULNERABLE_VAULT)
    text = fd._collect_text(ast)
    assert "flashSwap" in text
    assert "emergencySweep" in text


def test_get_ast_correctly_scopes_to_target_when_it_imports_openzeppelin(tmp_path):
    """Regression test for the real bug: before the fix, this returned
    Ownable.sol's own AST (the first key in solc's sources dict once the
    import resolved) instead of the target's. get_ast() always resolves
    the import via --base-path/--include-path pointed at this project's
    real ROOT/node_modules regardless of where the target file itself
    lives, so an isolated tmp_path is used here rather than writing into
    the real contracts/solidity/ (never registered in Zone 1's manifest,
    and no risk of a leftover file if this test ever crashed)."""
    probe = tmp_path / "_test_probe_ownable.sol"
    probe.write_text(
        '// SPDX-License-Identifier: MIT\n'
        'pragma solidity 0.8.24;\n'
        'import "@openzeppelin/contracts/access/Ownable.sol";\n'
        'contract ProbeOwnable is Ownable {\n'
        '    constructor() Ownable(msg.sender) {}\n'
        '    function probeMarkerFunction() external onlyOwner {}\n'
        '}\n'
    )
    ast = fd.get_ast(probe)
    text = fd._collect_text(ast)

    assert "probeMarkerFunction" in text  # the target's OWN declaration
    assert "onlyOwner" in text  # the modifier reference lives in the target's own AST
    assert "Ownable" in text  # the inheritance specifier's own name
    # The real regression: "renounceOwnership" is declared INSIDE Ownable.sol's
    # own, separate AST -- it must NOT appear just because the import resolved.
    assert "renounceOwnership" not in text


def test_get_ast_raises_honestly_when_target_key_is_genuinely_missing():
    with pytest.raises(RuntimeError):
        fd.get_ast(ROOT / "contracts" / "solidity" / "does-not-exist.sol")


# ---- real finding-count regression guards (Phase 4a before/after) --------

def test_vulnerable_vault_flashloan_findings_unchanged():
    """VulnerableVault.sol was never touched by the Phase 4a migration --
    locks in the exact real counts verified before and after."""
    flash, front = fd.analyze_contract(VULNERABLE_VAULT)
    assert len(flash) == 1
    assert flash[0]["function"] == "flashSwap"
    assert len(front) == 1
    assert front[0]["function"] == "flashSwap"


def test_secure_vault_flashloan_findings_still_zero_after_oz_migration():
    """SecureVault.sol's owner pattern was migrated to OpenZeppelin's
    Ownable this phase -- flash-loan shape is untouched by that migration,
    so this must still be exactly zero, same as before."""
    flash, front = fd.analyze_contract(SECURE_VAULT)
    assert flash == []
    assert front == []
