"""Real tests for scripts/pipeline-verdict.py.

The script is a standalone file (dash in the name, not importable normally),
so we load it via importlib from its real path on disk. ROOT and load_all
are monkeypatched per-test so nothing here ever touches the real reports/
directory.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT_DIR / "scripts" / "pipeline-verdict.py"


def load_module():
    spec = importlib.util.spec_from_file_location("pipeline_verdict", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def pv(tmp_path, monkeypatch):
    mod = load_module()
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    return mod


def ok(**extra):
    """A minimal 'ok' scanner result record."""
    d = {"status": "ok"}
    d.update(extra)
    return d


def all_required_ok(pv_mod, overrides=None):
    """Build a results dict where every REQUIRED scanner reports ok."""
    results = {name: ok() for name in pv_mod.REQUIRED}
    if overrides:
        results.update(overrides)
    return results


def run_main(pv_mod, monkeypatch, results, env=None):
    monkeypatch.setattr(pv_mod, "load_all", lambda: results)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    with pytest.raises(SystemExit) as exc_info:
        pv_mod.main()
    return exc_info.value.code


def read_verdict(pv_mod):
    return json.loads((pv_mod.ROOT / "reports" / "verdict.json").read_text())


# ---- happy path -----------------------------------------------------------

def test_all_ok_no_findings_is_pass_and_gitops_allowed(pv, monkeypatch):
    results = all_required_ok(pv)
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert code == 0
    assert out["health"] == "OK"
    assert out["verdict"] == "PASS"
    assert out["gitops_allowed"] is True
    assert out["health_problems"] == []
    assert out["halt_reasons"] == []


# ---- health failures --------------------------------------------------

def test_missing_required_scanner_fails_health_and_exits_2(pv, monkeypatch):
    results = all_required_ok(pv)
    del results["trivy"]  # not recorded at all -> "no result recorded"
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert code == 2
    assert out["health"] == "FAILED"
    assert any("trivy" in p and "no result recorded" in p for p in out["health_problems"])
    # no halt reasons were triggered, but health failed -> UNKNOWN, never PASS
    assert out["verdict"] == "UNKNOWN"
    assert out["gitops_allowed"] is False


def test_required_scanner_not_run_counts_as_health_problem(pv, monkeypatch):
    results = all_required_ok(pv, {"openscap": {"status": "not_run", "detail": "no datastream"}})
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert code == 2
    assert out["health"] == "FAILED"
    assert any("openscap: not_run" in p and "no datastream" in p for p in out["health_problems"])


def test_optional_scanner_missing_does_not_fail_health(pv, monkeypatch):
    results = all_required_ok(pv)
    del results["readiness"]
    code = run_main(pv, monkeypatch, results, env={"SOC_OPTIONAL": "readiness"})
    out = read_verdict(pv)
    assert code == 0
    assert out["health"] == "OK"
    assert out["scanners"]["readiness"]["policy"] == "optional"


# ---- halt reasons, one per scanner ----------------------------------------

def test_sca_high_findings_above_threshold_halts(pv, monkeypatch):
    results = all_required_ok(pv, {
        "sca": ok(counts={"npmAuditHigh": 7, "npmAuditCritical": 0}),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert code == 0  # health is still OK, only verdict halts
    assert out["verdict"] == "HALT"
    assert any("sca" in r and "7" in r for r in out["halt_reasons"])
    assert out["gitops_allowed"] is False


def test_sca_at_or_below_max_high_does_not_halt(pv, monkeypatch):
    results = all_required_ok(pv, {
        "sca": ok(counts={"npmAuditHigh": 0, "npmAuditCritical": 0}),
    })
    code = run_main(pv, monkeypatch, results, env={"SOC_MAX_HIGH": "0"})
    out = read_verdict(pv)
    assert code == 0
    assert out["verdict"] == "PASS"


def test_sonar_gate_error_halts(pv, monkeypatch):
    results = all_required_ok(pv, {"sonar": ok(gate="ERROR")})
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "HALT"
    assert any("sonarqube: quality gate ERROR" in r for r in out["halt_reasons"])


def test_trivy_and_zap_halt_reasons(pv, monkeypatch):
    results = all_required_ok(pv, {
        "trivy": ok(counts={"high": 2, "critical": 1}),
        "zap": ok(counts={"high": 3}),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert any(r.startswith("trivy: 3") for r in out["halt_reasons"])
    assert any(r.startswith("zap: 3") for r in out["halt_reasons"])


def test_readiness_block_ignored_without_enforce_flag(pv, monkeypatch):
    results = all_required_ok(pv, {"readiness": ok(decision="block", detail="hw-check-unconfigured")})
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "PASS"
    assert out["halt_reasons"] == []


def test_readiness_block_halts_when_enforced(pv, monkeypatch):
    results = all_required_ok(pv, {"readiness": ok(decision="block", detail="hw-check-unconfigured")})
    code = run_main(pv, monkeypatch, results, env={"ENFORCE_READINESS": "1"})
    out = read_verdict(pv)
    assert out["verdict"] == "HALT"
    assert any("readiness gate: block" in r and "hw-check-unconfigured" in r for r in out["halt_reasons"])


def test_allow_gitops_on_halt_overrides_pass_requirement(pv, monkeypatch):
    results = all_required_ok(pv, {"sonar": ok(gate="ERROR")})
    code = run_main(pv, monkeypatch, results, env={"ALLOW_GITOPS_ON_HALT": "1"})
    out = read_verdict(pv)
    assert out["verdict"] == "HALT"
    assert out["health"] == "OK"
    assert out["gitops_allowed"] is True


def test_gitops_never_allowed_when_health_failed_even_with_override(pv, monkeypatch):
    results = all_required_ok(pv)
    del results["mythril"]
    code = run_main(pv, monkeypatch, results, env={"ALLOW_GITOPS_ON_HALT": "1"})
    out = read_verdict(pv)
    assert out["health"] == "FAILED"
    assert out["gitops_allowed"] is False


# ---- SAST / slither path, including the sast-symbolic-report.json file ----

def write_sast_report(pv_mod, findings):
    reports_dir = pv_mod.ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "sast-symbolic-report.json").write_text(
        json.dumps({"target": "VulnerableVault.sol", "findings": findings})
    )


def test_sast_high_finding_with_check_key_halts(pv, monkeypatch):
    write_sast_report(pv, [{"impact": "HIGH", "check": "reentrancy-eth"}])
    results = all_required_ok(pv)
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "HALT"
    assert any("reentrancy-eth" in r for r in out["halt_reasons"])


def test_sast_low_findings_do_not_halt(pv, monkeypatch):
    write_sast_report(pv, [{"impact": "LOW", "check": "naming-convention"}])
    results = all_required_ok(pv)
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "PASS"


def test_sast_report_absent_does_not_crash(pv, monkeypatch):
    # No sast-symbolic-report.json written at all.
    results = all_required_ok(pv)
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "PASS"


# ---- regression tests for the two crash fixes ------------------------------

def test_sast_finding_missing_check_key_does_not_crash(pv, monkeypatch):
    """Regression: a HIGH/CRITICAL finding with no 'check' key used to raise
    KeyError on f["check"]. It must now fall back to 'unknown' and still halt."""
    write_sast_report(pv, [{"impact": "CRITICAL"}])  # no "check" key at all
    results = all_required_ok(pv)
    code = run_main(pv, monkeypatch, results)  # must not raise
    out = read_verdict(pv)
    assert out["verdict"] == "HALT"
    assert any("unknown" in r for r in out["halt_reasons"])


def write_echidna_report(pv_mod, properties):
    reports_dir = pv_mod.ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "echidna-report.json").write_text(json.dumps({"properties": properties}))


# ---- Phase 2 gating: flashloan-detector / rugpull-detector ----------------

def test_flashloan_detector_finding_halts(pv, monkeypatch):
    results = all_required_ok(pv, {
        "flashloan-detector": ok(counts={"flashloan_findings": 1, "frontrunning_findings": 0}),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert code == 0  # health still OK, only verdict halts
    assert out["verdict"] == "HALT"
    assert any("flashloan-detector: 1 flash-loan-shape" in r for r in out["halt_reasons"])


def test_frontrunning_finding_alone_halts(pv, monkeypatch):
    results = all_required_ok(pv, {
        "flashloan-detector": ok(counts={"flashloan_findings": 0, "frontrunning_findings": 1}),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "HALT"
    assert any("1 front-running finding" in r for r in out["halt_reasons"])


def test_flashloan_detector_zero_findings_does_not_halt(pv, monkeypatch):
    results = all_required_ok(pv, {
        "flashloan-detector": ok(counts={"flashloan_findings": 0, "frontrunning_findings": 0}),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "PASS"


def test_rugpull_detector_failing_check_halts(pv, monkeypatch):
    results = all_required_ok(pv, {
        "rugpull-detector": ok(counts={"targets": 1, "failing_checks": 2}),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "HALT"
    assert any("rugpull-detector: 2 failing rug-pull check(s)" in r for r in out["halt_reasons"])


def test_rugpull_detector_zero_failing_checks_does_not_halt(pv, monkeypatch):
    results = all_required_ok(pv, {
        "rugpull-detector": ok(counts={"targets": 1, "failing_checks": 0}),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "PASS"


def test_defi_detector_not_run_does_not_halt(pv, monkeypatch):
    results = all_required_ok(pv, {
        "flashloan-detector": {"status": "not_run"},
        "rugpull-detector": {"status": "not_run"},
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "PASS"


# ---- Phase 2 gating: chain_attack_monitor is intentionally NOT gated ------

def test_chain_attack_monitor_critical_does_not_halt(pv, monkeypatch):
    """chain_attack_monitor's findings are a fixed single-node Anvil demo,
    completely decoupled from TARGET_CONTRACT (verified: 7/7 checks trigger
    CRITICAL/CRITICAL_ATTACK on every real run regardless of target). This
    proves the exclusion is intentional: even the worst real result from
    every one of its four sub-detectors must not affect the verdict."""
    results = all_required_ok(pv, {
        "consensus-attack": ok(
            counts={"checks": 7, "triggered": 7},
            reorg_severity="CRITICAL_FINALITY_VIOLATION",
            concentration_alert="CRITICAL",
            eclipse_threat_level="CRITICAL",
            selfish_mining_threat_level="CRITICAL_ATTACK",
        ),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "PASS"
    assert out["halt_reasons"] == []
    assert not any("consensus-attack" in r or "chain-attack" in r for r in out["halt_reasons"])


# ---- Phase 2 gating: Echidna, balance invariant only ----------------------

def test_echidna_balance_invariant_falsified_halts(pv, monkeypatch):
    write_echidna_report(pv, [
        {"name": "echidna_internal_balance_never_exceeds_contract_eth", "passed": False, "detail": "failed!"},
        {"name": "echidna_withdraw_never_reentered", "passed": False, "detail": "failed!"},
    ])
    results = all_required_ok(pv, {
        "echidna": ok(counts={"properties_total": 2, "properties_passing": 0, "properties_failing": 2}),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "HALT"
    assert any("echidna_internal_balance_never_exceeds_contract_eth FALSIFIED" in r for r in out["halt_reasons"])


def test_echidna_reentrancy_invariant_falsified_alone_does_not_halt(pv, monkeypatch):
    """The known, documented property-design limitation: reentrancy-never
    invariant fails on BOTH the vulnerable and the secure harness (verified
    by actually running Echidna against SecureVaultEchidnaHarness.sol), so
    it must never gate the verdict by itself."""
    write_echidna_report(pv, [
        {"name": "echidna_internal_balance_never_exceeds_contract_eth", "passed": True, "detail": "passing"},
        {"name": "echidna_withdraw_never_reentered", "passed": False, "detail": "failed!"},
    ])
    results = all_required_ok(pv, {
        "echidna": ok(counts={"properties_total": 2, "properties_passing": 1, "properties_failing": 1}),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "PASS"
    assert out["halt_reasons"] == []


def test_echidna_both_properties_passing_does_not_halt(pv, monkeypatch):
    write_echidna_report(pv, [
        {"name": "echidna_internal_balance_never_exceeds_contract_eth", "passed": True, "detail": "passing"},
        {"name": "echidna_withdraw_never_reentered", "passed": True, "detail": "passing"},
    ])
    results = all_required_ok(pv, {
        "echidna": ok(counts={"properties_total": 2, "properties_passing": 2, "properties_failing": 0}),
    })
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "PASS"


def test_echidna_not_run_does_not_halt(pv, monkeypatch):
    # No echidna-report.json written, status not_run -- must not crash or halt.
    results = all_required_ok(pv, {"echidna": {"status": "not_run"}})
    code = run_main(pv, monkeypatch, results)
    out = read_verdict(pv)
    assert out["verdict"] == "PASS"


def test_unrecognized_scanner_status_does_not_crash_summary_print(pv, monkeypatch, capsys):
    """Regression: a status outside {ok, not_run, error} used to raise KeyError
    on the icon-lookup dict while printing the summary table. It must now
    print a '[?]' fallback instead, and the run must still finish and write
    verdict.json."""
    results = all_required_ok(pv, {"readiness": {"status": "skipped"}})
    code = run_main(pv, monkeypatch, results)  # must not raise
    out_text = capsys.readouterr().out
    assert "[?]" in out_text
    out = read_verdict(pv)
    # an unrecognized status for a required scanner still fails health
    assert out["health"] == "FAILED"
    assert code == 2