"""
Phase 1 (gap-closure): unit tests for the Stage 5 third signing/approval layer
wiring in src/wallet/quorum_signer.py -- a real 2-of-3 Shamir quorum
reconstruct -> 2-party MPC joint ECDSA sign+verify over the same pipeline
attestation string Vault/HSM co-sign.

These tests exercise the WIRING itself (share loading, honest-skip, the
real end-to-end round trip, and write_result contract compliance), not the
underlying crypto primitives -- those already have dedicated coverage in
test/wallet/test_hsm_emulator.py and the Shamir/MPC modules' own test files.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from src.wallet import quorum_signer as qs  # noqa: E402
from src.wallet.shamir_engine import ShamirSecretSharing  # noqa: E402


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    """Redirect the quorum share dir and report-writing root to a throwaway
    directory so tests never touch the real ~/.local/state/soc-quorum or
    reports/ tree."""
    share_dir = tmp_path / "shares"
    share_dir.mkdir()
    monkeypatch.setattr(qs, "SHARE_DIR", share_dir)
    monkeypatch.setattr(qs, "ROOT", tmp_path)
    import scanner_result as sr  # noqa: E402 (same module quorum_signer binds write_result from)
    monkeypatch.setattr(sr, "RESULTS", tmp_path / "scanners")
    monkeypatch.setattr(sr, "RAW", tmp_path / "raw")
    return share_dir, tmp_path


def _write_real_shares(share_dir, threshold=2, total=3, secret=None):
    secret = secret or bytes(range(32))
    engine = ShamirSecretSharing()
    shares = engine.split_secret(secret, threshold=threshold, total_shares=total)
    for s in shares:
        (share_dir / f"share-{s.index}.json").write_text(
            json.dumps(s.to_dict()), encoding="utf-8")
    return shares


def test_load_shares_empty_dir_returns_empty(isolated_env):
    share_dir, _ = isolated_env
    assert qs._load_shares() == []


def test_load_shares_ignores_corrupt_file(isolated_env):
    share_dir, _ = isolated_env
    _write_real_shares(share_dir)
    (share_dir / "share-99.json").write_text("not valid json {{{", encoding="utf-8")
    loaded = qs._load_shares()
    assert len(loaded) == 3  # the 3 real shares, corrupt one skipped
    assert all(hasattr(s, "index") for s in loaded)


def test_run_quorum_signing_honest_skip_when_shares_absent(isolated_env):
    with pytest.raises(RuntimeError) as exc:
        qs.run_quorum_signing(b"ATTESTATION:test-target:PIPELINE_RUN")
    msg = str(exc.value)
    assert "0 real share" in msg
    assert "2-of-3" in msg
    assert "provision-quorum-shares.py" in msg


def test_run_quorum_signing_honest_skip_below_threshold(isolated_env):
    share_dir, _ = isolated_env
    _write_real_shares(share_dir)
    (share_dir / "share-1.json").unlink()
    (share_dir / "share-2.json").unlink()
    with pytest.raises(RuntimeError) as exc:
        qs.run_quorum_signing(b"ATTESTATION:test-target:PIPELINE_RUN")
    assert "1 real share" in str(exc.value)


def test_run_quorum_signing_real_round_trip(isolated_env):
    share_dir, _ = isolated_env
    _write_real_shares(share_dir)
    message = b"ATTESTATION:test-target:PIPELINE_RUN"

    result = qs.run_quorum_signing(message)

    assert result["quorum_threshold"] == 2
    assert result["quorum_total_shares"] == 3
    assert len(result["shares_used"]) == 2
    assert result["message"] == message.decode()
    assert result["joint_signature_verified"] is True
    assert result["key_material_isolated"] is True
    assert result["joint_signature_len_bytes"] == 65
    assert result["cluster_address"].startswith("0x")
    # digest must be the real sha256 of the attestation, not the raw message
    import hashlib
    assert result["digest_sha256_hex"] == hashlib.sha256(message).hexdigest()


def test_run_quorum_signing_tamper_detection(isolated_env):
    """The same reconstruct -> provision -> sign chain run_quorum_signing uses
    must reject a signature when checked against a DIFFERENT digest than the
    one it actually signed -- proves verify_joint_signature is a real check,
    not a tautology that always returns True for this cluster."""
    share_dir, _ = isolated_env
    shares = _write_real_shares(share_dir)
    from src.wallet.shamir_engine import zero_buffer
    from src.wallet.mpc_relayer_cluster import MpcRelayerCluster
    from src.wallet.mpc_joint_signer import MpcJointSigner
    from src.wallet.hsm_emulator import _N
    import hashlib

    engine = ShamirSecretSharing()
    reconstructed = bytearray(engine.reconstruct_secret(shares[:2]))
    full_key = int.from_bytes(bytes(reconstructed), "big") % _N or 1
    zero_buffer(reconstructed)

    cluster = MpcRelayerCluster(cluster_id="quorum-attestation-cluster")
    cluster.provision_relayer_key(full_key=full_key)
    signer = MpcJointSigner(cluster)

    real_digest = hashlib.sha256(b"ATTESTATION:test-target:PIPELINE_RUN").digest()
    sig = signer.sign_transaction_digest(real_digest)
    assert signer.verify_joint_signature(real_digest, sig) is True

    other_digest = hashlib.sha256(b"different message").digest()
    assert signer.verify_joint_signature(other_digest, sig) is False


def test_main_writes_not_run_result_when_shares_absent(isolated_env, monkeypatch, capsys):
    monkeypatch.setenv("TARGET_NAME", "UnitTestTarget")
    qs.main()
    out = capsys.readouterr().out
    assert "not_run" in out

    # scanner_result.RESULTS was monkeypatched to tmp_path/scanners, the same
    # tmp_path qs.ROOT points at -- read the written result from there.
    written = json.loads((qs.ROOT / "scanners" / "quorum-signer.json").read_text())
    assert written["status"] == "not_run"
    assert written["name"] == "quorum-signer"
    assert "2-of-3" in written["detail"]


def test_main_writes_ok_result_with_real_shares(isolated_env, monkeypatch, capsys):
    share_dir, tmp_path = isolated_env
    _write_real_shares(share_dir)
    monkeypatch.setenv("TARGET_NAME", "UnitTestTarget")

    qs.main()

    out = capsys.readouterr().out
    assert "quorum-signer: ok" in out

    written = json.loads((qs.ROOT / "scanners" / "quorum-signer.json").read_text())
    assert written["status"] == "ok"
    assert written["counts"]["quorum_threshold"] == 2
    assert written["counts"]["quorum_total_shares"] == 3
    assert written["cluster_address"].startswith("0x")

    report_file = tmp_path / "reports" / "quorum-signer-report.json"
    assert report_file.is_file()
    full = json.loads(report_file.read_text())
    assert full["message"] == "ATTESTATION:UnitTestTarget:PIPELINE_RUN"
    assert full["joint_signature_verified"] is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
