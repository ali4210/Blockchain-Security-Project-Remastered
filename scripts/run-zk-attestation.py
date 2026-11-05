#!/usr/bin/env python3
"""Zone 3 (compliance): real ZK compliance attestation over this run's own
OFAC-screened addresses.

Wires src/compliance/zk_attestation.py (SimpleZKAttestor) into the live
pipeline. This runs AFTER run-ofac-screening.py in the same zone and reuses
that step's own real output (reports/ofac-screening-report.json) -- the
same real addresses this run actually screened, not a separately invented
scenario.

WHY THIS MAPPING (not SAST findings): SimpleZKAttestor.generate_attestation()
takes (sender_address, volume_wei, max_threshold_wei,
known_sanctioned_addresses) and proves "this address is not on the
sanctioned list and this volume is under some threshold" WITHOUT revealing
the address or volume to a verifier. That is a real AML/sanctions-screening
primitive -- it has nothing to do with SAST findings, and forcing a
SAST-shaped use would misrepresent what the function actually proves.

HONEST SCOPE (read before trusting any "ZK" label here):
  * src/compliance/zk_attestation.py's own docstring calls this a
    "Simplified ZK Compliance Attestation Engine" -- Pedersen-style SHA-256
    commitments + a Merkle-root field + a Fiat-Shamir/HMAC challenge-
    response. This is NOT a real zk-SNARK/zk-STARK circuit: there is no
    arithmetic circuit, no trusted setup or transparent setup, no
    succinctness proof, and no formal zero-knowledge/soundness proof the
    way libsnark/circom/halo2 would provide. It is a real, working
    commitment + challenge-response scheme that hides the address/volume
    from a verifier who only sees the public ComplianceProof -- genuinely
    useful, just not cryptographically equivalent to a SNARK/STARK. Every
    report/HTML label below says "simplified ZK (commitment-based)", never
    bare "ZK-SNARK" or "zero-knowledge proof" unqualified.
  * Volume/threshold values are a documented DEMONSTRATION canary (same
    convention as run-ofac-screening.py / run-kyc-screening.py): this
    fixture pipeline has no real transaction volume data to draw from.
    Override via TARGET_ZK_VOLUME_WEI / TARGET_ZK_THRESHOLD_WEI for a real
    operator-supplied scenario.
  * The private witness (blinding factors) is NEVER written to any report
    file -- writing it would defeat the entire point of a hiding
    commitment. Only the public ComplianceProof fields are persisted.
  * generate_attestation() correctly RAISES (refuses to produce a proof)
    for a genuinely sanctioned address -- that refusal is reported as a
    real, honest "refused" result, never silently skipped or miscounted
    as a failure of this scanner.

Honest status via scanner_result:
  not_run  -- this run's own ofac-screening report is missing/not ok
  error    -- every attempted attestation raised unexpectedly (not the
              expected ValueError-on-sanctioned-address refusal)
  ok       -- at least one real attestation was attempted (succeeded or
              correctly refused) and, for each success, independently
              re-verified both with and without the private witness
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402
from src.compliance.zk_attestation import SimpleZKAttestor, ComplianceProof  # noqa: E402
from src.compliance.address_screener import AddressScreener, SnapshotUnavailable  # noqa: E402

DEMO_VOLUME_WEI = int(os.environ.get("TARGET_ZK_VOLUME_WEI", 10**18))          # 1 ETH
DEMO_THRESHOLD_WEI = int(os.environ.get("TARGET_ZK_THRESHOLD_WEI", 10 * 10**18))  # 10 ETH


def _proof_to_public_dict(proof: ComplianceProof) -> dict:
    """Every field here is PUBLIC by the scheme's own design -- the whole
    point of a hiding commitment is that these reveal nothing about the
    real address/volume. The witness (blinding factors) is a separate
    object this function never receives and never writes."""
    return {
        "proof_id": proof.proof_id,
        "nullifier_hash": proof.nullifier_hash,
        "address_commitment": proof.address_commitment,
        "volume_commitment": proof.volume_commitment,
        "max_threshold_wei": proof.max_threshold_wei,
        "merkle_root": proof.merkle_root,
        "challenge": proof.challenge,
        "response_signature": proof.response_signature,
        "is_sanctions_free": proof.is_sanctions_free,
    }


def main():
    print("[+] [ZONE 3] Simplified ZK compliance attestation (commitment-based, NOT a zk-SNARK/STARK)...")

    ofac_report_path = ROOT / "reports" / "ofac-screening-report.json"
    if not ofac_report_path.is_file():
        return write_result("zk-attestation", "simple-zk-attestor", "not_run",
                            detail="this run's reports/ofac-screening-report.json is missing")
    try:
        ofac_report = json.loads(ofac_report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return write_result("zk-attestation", "simple-zk-attestor", "not_run",
                            detail=f"ofac-screening-report.json unreadable: {str(exc)[:150]}")

    screened = ofac_report.get("screened") or []
    if not screened:
        return write_result("zk-attestation", "simple-zk-attestor", "not_run",
                            detail="this run's OFAC screening screened zero addresses")

    try:
        screener = AddressScreener()
    except SnapshotUnavailable as exc:
        return write_result("zk-attestation", "simple-zk-attestor", "not_run",
                            detail=f"OFAC snapshot unavailable for the real sanctioned-address list: {str(exc)[:150]}")

    # The REAL full OFAC SDN address list this run's own screening step just
    # checked against -- not a separately invented list.
    known_sanctioned = [r.get("address", "") for r in screener._records if r.get("address")]
    attestor = SimpleZKAttestor()

    results = []
    try:
        for row in screened:
            addr = row.get("address", "")
            entry = {"address": addr, "volume_wei": DEMO_VOLUME_WEI,
                     "max_threshold_wei": DEMO_THRESHOLD_WEI}
            try:
                proof, witness = attestor.generate_attestation(
                    addr, DEMO_VOLUME_WEI, DEMO_THRESHOLD_WEI, known_sanctioned)
                verified_with_witness = attestor.verify_attestation(proof, witness)
                verified_public_only = attestor.verify_attestation(proof, witness=None)
                entry.update({
                    "outcome": "proof_generated",
                    "proof": _proof_to_public_dict(proof),
                    "verified_with_witness": verified_with_witness,
                    "verified_public_only": verified_public_only,
                })
                print(f"    -> {addr}: proof generated ({proof.proof_id}), "
                      f"verified_with_witness={verified_with_witness}, "
                      f"verified_public_only={verified_public_only}")
            except ValueError as exc:
                # Correctly refused -- the scheme's own sanctioned-address
                # invariant check working as designed. A real, honest result,
                # not an error.
                entry.update({"outcome": "refused", "refusal_reason": str(exc)[:200]})
                print(f"    -> {addr}: attestation correctly REFUSED ({str(exc)[:80]})")
            results.append(entry)
    except Exception as exc:  # noqa: BLE001 -- genuinely unexpected failure
        return write_result("zk-attestation", "simple-zk-attestor", "error", detail=str(exc)[:200])

    generated = sum(1 for r in results if r["outcome"] == "proof_generated")
    refused = sum(1 for r in results if r["outcome"] == "refused")
    all_verified = all(r.get("verified_with_witness") and r.get("verified_public_only")
                       for r in results if r["outcome"] == "proof_generated")

    report = {
        "scheme": "simplified-zk-commitment-challenge-response",
        "scheme_honest_label": "Pedersen-style SHA-256 commitments + Fiat-Shamir/HMAC "
                               "challenge-response -- NOT a zk-SNARK/zk-STARK circuit",
        "mode": "demonstration-volume-threshold" if "TARGET_ZK_VOLUME_WEI" not in os.environ else "operator-supplied",
        "demo_volume_wei": DEMO_VOLUME_WEI,
        "demo_threshold_wei": DEMO_THRESHOLD_WEI,
        "sanctioned_universe_size": len(known_sanctioned),
        "ofac_snapshot_meta": {k: screener.snapshot_meta.get(k)
                               for k in ("source_url", "downloaded_at", "address_count")},
        "attestations": results,
    }
    report_file = ROOT / "reports" / "zk-attestation-report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    detail = (f"{generated} proof(s) generated (all independently re-verified: {all_verified}), "
              f"{refused} correctly refused as sanctioned, over {len(screened)} address(es) "
              f"this run's own OFAC screening checked -- simplified commitment-based scheme, "
              f"not a zk-SNARK/STARK")
    print(f"    -> {detail}")
    return write_result("zk-attestation", "simple-zk-attestor", "ok", raw_report=report_file,
                        detail=detail,
                        counts={"proofs_generated": generated, "refused_sanctioned": refused},
                        extra={"all_verified": all_verified})


if __name__ == "__main__":
    main()
