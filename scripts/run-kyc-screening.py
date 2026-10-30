#!/usr/bin/env python3
"""Zone: KYC/AML sanctions & PEP name-screening gate.

Screens one or more names against the REAL OpenSanctions Consolidated
Sanctions snapshot (scripts/mirror-opensanctions.py builds it;
src/compliance/kyc_verifier.py matches). V1 scope is name screening only --
see kyc_verifier.py's module docstring for why full biometric KYC is a
documented v2 step, not implemented here.

Names screened:
  * TARGET_SCREEN_NAME env (comma-separated) if set -- the real name(s) the
    operator wants checked (e.g. a counterparty / beneficial owner).
  * otherwise a DEMONSTRATION canary pair: one documented, verified
    sanctions-listed name (must flag) and one clean control (must not). This
    local fixture pipeline has no real external counterparty, so the default
    is explicitly a capability demonstration, not a live screen.

Any CONFIRMED or INCONCLUSIVE match additionally produces a DraftKycReview
(src/compliance/kyc_verifier.py's HITL governance layer) -- DRAFT_PENDING_REVIEW,
requires_human_approval=True. Nothing here auto-blocks or auto-clears anything.

Honest status via scanner_result:
  * not_run  -- snapshot missing or stale (never a guessed clean result)
  * error    -- screening raised unexpectedly
  * ok       -- screening really ran against a present, current snapshot
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402
from src.compliance.kyc_verifier import (  # noqa: E402
    KycReviewGenerator,
    KycScreener,
    MatchConfidence,
    OpenSanctionsSnapshotUnavailable,
)

# Documented demonstration canary: "Lazarus Group" is verified present (as of
# this writing) in the real OpenSanctions sanctions collection -- DPRK
# state-sponsored actor, OFAC SDN / multiple national sanctions lists, with a
# long real alias list (APT38, Bluenoroff, Hidden Cobra, ...). Clean control
# is a made-up name chosen to not collide with any real entity.
CANARY_SANCTIONED = "Lazarus Group"
CANARY_CLEAN = "Harriet Quilborne-Fenwick"


def targets():
    env = os.getenv("TARGET_SCREEN_NAME", "").strip()
    if env:
        return [n.strip() for n in env.split(",") if n.strip()], False
    return [CANARY_SANCTIONED, CANARY_CLEAN], True


def main():
    print("[+] [COMPLIANCE] OpenSanctions KYC/AML name screening...")
    try:
        screener = KycScreener()
    except OpenSanctionsSnapshotUnavailable as exc:
        return write_result("kyc-screening", "opensanctions", "not_run", detail=str(exc)[:200])

    names, is_demo = targets()
    generator = KycReviewGenerator()
    try:
        results = []
        reviews = []
        for idx, name in enumerate(names):
            m = screener.screen(name)
            results.append({
                "queried_name": name,
                "flagged": m.is_flagged,
                "confidence": m.confidence.value,
                "score": round(m.score, 3),
                "reason": m.reason,
                "entity": m.matched_entity.name if m.matched_entity else None,
            })
            mark = "FLAGGED" if m.is_flagged else "clean"
            print(f"    -> {name!r}: {mark} ({m.confidence.value}, score={m.score:.3f}) -- {m.reason}")
            if m.confidence != MatchConfidence.NO_MATCH:
                draft = generator.generate_draft(case_id=f"KYC-{idx}-{abs(hash(name)) % 10**8}", match=m)
                reviews.append({
                    "review_id": draft.review_id,
                    "status": draft.status.value,
                    "requires_human_approval": draft.requires_human_approval,
                    "digest_verified": KycReviewGenerator.verify_draft_integrity(draft),
                })
                print(f"       -> draft review {draft.review_id}: {draft.status.value}, "
                      f"requires_human_approval={draft.requires_human_approval}")
    except Exception as exc:  # noqa: BLE001
        return write_result("kyc-screening", "opensanctions", "error", detail=str(exc)[:200])

    flagged = sum(1 for r in results if r["flagged"])
    meta = screener.snapshot_meta
    report = {
        "mode": "demonstration-canary" if is_demo else "operator-supplied",
        "snapshot": {k: meta.get(k) for k in
                     ("source", "source_dataset", "downloaded_at", "csv_sha256", "entity_count", "license")},
        "screened": results,
        "draft_reviews": reviews,
    }
    report_file = ROOT / "reports" / "kyc-screening-report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    note = (" (DEMONSTRATION canary: no real counterparty in this fixture pipeline)"
            if is_demo else "")
    detail = (f"screened {len(results)} name(s), {flagged} flagged ({len(reviews)} draft review(s)) "
              f"against OpenSanctions snapshot {meta.get('downloaded_at')} "
              f"({meta.get('entity_count')} entities){note}")
    return write_result("kyc-screening", "opensanctions", "ok",
                        counts={"screened": len(results), "flagged": flagged,
                                "clean": len(results) - flagged, "draft_reviews": len(reviews)},
                        raw_report=report_file, detail=detail,
                        extra={"mode": report["mode"]})


if __name__ == "__main__":
    main()
