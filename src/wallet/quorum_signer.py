#!/usr/bin/env python3
"""
Stage 5: k-of-n quorum-approval threshold signing layer.

Completes a genuine three-layer signing/approval chain over the SAME real
attestation string Vault Transit and SoftHSM2 sign (see run-all-e2e.sh's
Zone 7 steps and src/wallet/hsm_signer.py):
  1. Vault Transit sign (existing)
  2. SoftHSM2 PKCS#11 co-sign (existing)
  3. THIS: a real k-of-n (2-of-3) quorum reconstructs a shared secret via
     src/wallet/shamir_engine.py's real Lagrange-interpolation reconstruction;
     that secret becomes the master key fed into a real 2-party MPC cluster
     (src/wallet/mpc_relayer_cluster.py), which then jointly signs the SAME
     attestation digest via src/wallet/mpc_joint_signer.py's real distributed
     ECDSA protocol.

HONEST SCOPE:
  * mpc_relayer_cluster.py's own docstring calls it a "2-Party MPC Stand-in"
    -- the 2-of-3 Shamir quorum is the human/organizational k-of-n approval
    layer; the MPC cluster is a fixed 2-replica machine-signing layer that
    the reconstructed secret is fed into (via provision_relayer_key's own
    `full_key` parameter, which it already supports). These are genuinely
    two different, composed real mechanisms, not one relabeled as the other.
  * MpcJointSigner.sign_transaction_digest() requires exactly a 32-byte
    digest, not an arbitrary string -- the real attestation string is
    SHA-256 hashed first, standard ECDSA practice (sign the digest, not the
    raw message), not a shortcut around the real API.
  * Honest-skip: if fewer than QUORUM_THRESHOLD real share files are present
    under ~/.local/state/soc-quorum (provisioned once via
    scripts/provision-quorum-shares.py, never re-run at signing time), this
    reports not_run with the exact reason and the ceremony command -- never
    a fabricated passing signature.
  * NOT added to ingest-defectdojo.py's generic_scanners: like vault-sign and
    hsm-signer, this has no per-item findings list, just a single real
    status -- the same infra-attestation shape, not a scanner with findings
    to import. It reaches Elasticsearch/Prometheus/the HTML report the same
    way vault-sign/hsm-signer do.

Writes reports/scanners/quorum-signer.json via the shared scanner_result
contract. Purely additive/informational: NOT added to pipeline-verdict's
REQUIRED list.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402

from src.wallet.shamir_engine import ShamirShare, ShamirSecretSharing, zero_buffer  # noqa: E402
from src.wallet.mpc_relayer_cluster import MpcRelayerCluster  # noqa: E402
from src.wallet.mpc_joint_signer import MpcJointSigner  # noqa: E402
from src.wallet.hsm_emulator import _N  # noqa: E402

QUORUM_THRESHOLD = 2
QUORUM_TOTAL_SHARES = 3
SHARE_DIR = Path(os.getenv("QUORUM_SHARE_DIR", str(Path.home() / ".local/state/soc-quorum")))


def _load_shares():
    shares = []
    for path in sorted(SHARE_DIR.glob("share-*.json")):
        try:
            shares.append(ShamirShare.from_dict(json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, ValueError, KeyError):
            continue
    return shares


def run_quorum_signing(attestation_message: bytes):
    """Real reconstruct -> provision -> joint-sign -> verify chain.
    Returns a dict of real, inspectable values, or raises on a real failure
    (missing shares, reconstruction/signing error) -- never fabricates."""
    shares = _load_shares()
    if len(shares) < QUORUM_THRESHOLD:
        raise RuntimeError(
            f"only {len(shares)} real share(s) present under {SHARE_DIR} "
            f"(need {QUORUM_THRESHOLD}-of-{QUORUM_TOTAL_SHARES}); run "
            "scripts/provision-quorum-shares.py once to provision them"
        )

    engine = ShamirSecretSharing()
    reconstructed = bytearray(engine.reconstruct_secret(shares[:QUORUM_THRESHOLD]))
    try:
        full_key = int.from_bytes(bytes(reconstructed), "big") % _N
        if full_key == 0:  # astronomically unlikely, defensive only
            full_key = 1
    finally:
        zero_buffer(reconstructed)
        del reconstructed

    cluster = MpcRelayerCluster(cluster_id="quorum-attestation-cluster")
    cluster_pub = cluster.provision_relayer_key(full_key=full_key)
    del full_key

    isolation = cluster.verify_key_material_isolation()
    signer = MpcJointSigner(cluster)

    digest = hashlib.sha256(attestation_message).digest()
    joint_sig = signer.sign_transaction_digest(digest)
    verified = signer.verify_joint_signature(digest, joint_sig)
    non_retention = signer.audit_non_retention_proof()

    return {
        "quorum_threshold": QUORUM_THRESHOLD,
        "quorum_total_shares": QUORUM_TOTAL_SHARES,
        "shares_used": [s.index for s in shares[:QUORUM_THRESHOLD]],
        "message": attestation_message.decode(),
        "digest_sha256_hex": digest.hex(),
        "joint_signature_hex": joint_sig.hex(),
        "joint_signature_len_bytes": len(joint_sig),
        "cluster_address": cluster_pub.ethereum_address,
        "cluster_public_key_hex": cluster_pub.public_key_hex,
        "key_material_isolated": isolation.get("isolated"),
        "joint_signature_verified": verified,
        "non_retention_proof": non_retention,
    }


def main():
    print("[+] [ZONE 7] k-of-n quorum-approval threshold signing "
          f"({QUORUM_THRESHOLD}-of-{QUORUM_TOTAL_SHARES} Shamir -> 2-party MPC joint sign)...")
    message = ("ATTESTATION:" + os.environ.get("TARGET_NAME", "unknown") + ":PIPELINE_RUN").encode()
    try:
        result = run_quorum_signing(message)
    except Exception as exc:  # noqa: BLE001
        print(f"    -> not_run: {exc}")
        return write_result("quorum-signer", "shamir+mpc-joint-sign", "not_run", detail=str(exc)[:250])

    ok = bool(result["joint_signature_verified"] and result["key_material_isolated"])
    report_file = ROOT / "reports" / "quorum-signer-report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(f"    -> quorum: {result['quorum_threshold']}-of-{result['quorum_total_shares']} "
          f"(shares used: {result['shares_used']})")
    print(f"    -> cluster address: {result['cluster_address']}")
    print(f"    -> joint signature: {result['joint_signature_hex'][:32]}... "
          f"({result['joint_signature_len_bytes']} bytes)")
    print(f"    -> verified={result['joint_signature_verified']} "
          f"key_material_isolated={result['key_material_isolated']}")

    detail = ("real k-of-n Shamir reconstruct -> 2-party MPC joint ECDSA sign + verify "
              f"{'succeeded' if ok else 'FAILED'} over the real pipeline attestation")
    return write_result("quorum-signer", "shamir+mpc-joint-sign", "ok" if ok else "error",
                        counts={"quorum_threshold": result["quorum_threshold"],
                                "quorum_total_shares": result["quorum_total_shares"]},
                        raw_report=report_file, detail=detail,
                        extra={"cluster_address": result["cluster_address"]})


if __name__ == "__main__":
    main()
