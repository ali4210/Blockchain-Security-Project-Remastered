import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import scanner_result as sr  # noqa: E402


@pytest.fixture
def isolated_reports(tmp_path, monkeypatch):
    """Redirect RESULTS/RAW/ROOT to a throwaway directory so tests never
    touch the real reports/ folder."""
    results_dir = tmp_path / "scanners"
    raw_dir = tmp_path / "raw"
    monkeypatch.setattr(sr, "RESULTS", results_dir)
    monkeypatch.setattr(sr, "RAW", raw_dir)
    monkeypatch.setattr(sr, "ROOT", tmp_path)
    return results_dir, raw_dir


def test_write_result_ok_minimal(isolated_reports, capsys):
    results_dir, _ = isolated_reports
    rec = sr.write_result("trivy", "trivy", "ok", counts={"high": 1})
    out = capsys.readouterr().out
    assert "[+] trivy: ok" in out
    assert rec["status"] == "ok"
    assert rec["counts"] == {"high": 1}
    written = json.loads((results_dir / "trivy.json").read_text())
    assert written["name"] == "trivy"
    assert written["tool"] == "trivy"
    assert written["status"] == "ok"


def test_write_result_rejects_bad_status(isolated_reports):
    with pytest.raises(ValueError):
        sr.write_result("x", "x", "nope")


def test_write_result_not_run_prints_bang(isolated_reports, capsys):
    sr.write_result("openscap", "openscap", "not_run", detail="no datastream")
    out = capsys.readouterr().out
    assert "[!] openscap: not_run" in out
    assert "no datastream" in out


def test_write_result_error_prints_minus(isolated_reports, capsys):
    sr.write_result("sonar", "sonarqube", "error", detail="boom")
    out = capsys.readouterr().out
    assert "[-] sonar: error" in out


def test_write_result_hashes_raw_report(isolated_reports):
    results_dir, raw_dir = isolated_reports
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_file = raw_dir / "slither.sarif"
    raw_file.write_text("some sarif content")
    rec = sr.write_result("slither", "slither", "ok", raw_report=raw_file)
    assert rec["raw_sha256"] == sr.sha256_file(raw_file)
    assert rec["raw_report"] is not None


def test_write_result_missing_raw_report_has_no_hash(isolated_reports):
    _, raw_dir = isolated_reports
    missing = raw_dir / "does-not-exist.json"
    rec = sr.write_result("mythril", "mythril", "ok", raw_report=missing)
    assert rec["raw_sha256"] is None


def test_write_result_extra_merges_into_record(isolated_reports):
    rec = sr.write_result(
        "sast-canary", "canary", "ok",
        extra={"primary_target": "VulnerableVault.sol"},
    )
    assert rec["primary_target"] == "VulnerableVault.sol"


def test_load_all_reads_every_written_result(isolated_reports):
    sr.write_result("trivy", "trivy", "ok")
    sr.write_result("zap", "zap", "ok")
    loaded = sr.load_all()
    assert set(loaded) == {"trivy", "zap"}
    assert loaded["trivy"]["status"] == "ok"


def test_load_all_handles_unreadable_json(isolated_reports):
    results_dir, _ = isolated_reports
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "broken.json").write_text("{not valid json")
    loaded = sr.load_all()
    assert loaded["broken"]["status"] == "error"


def test_load_all_empty_when_no_results_dir(isolated_reports):
    assert sr.load_all() == {}


def test_sha256_file_matches_known_hash(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"hello world")
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert sr.sha256_file(f) == expected