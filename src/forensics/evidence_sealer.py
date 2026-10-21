"""Seal the real artifacts of a pipeline run into one verifiable digest.

The forensic hasher and evidence DB are real; what was missing was feeding them
the ACTUAL run output. This module collects the real report files produced this
run, hashes each, builds a manifest, and derives a single root SHA-256/512 over
that manifest. The root digest changes whenever any sealed evidence changes, so
it is a genuine seal of this run's content — not the constant
b'LIVE_PIPELINE_RUN_ARTIFACT' the pipeline used to hash.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Candidate real evidence files; only those present this run are sealed.
EVIDENCE_CANDIDATES = [
    "reports/verdict.json",
    "reports/sast-symbolic-report.json",
    "reports/avs-consensus-report.json",
    "reports/ofac-screening-report.json",
    "reports/swarm-execution-report.json",
    "reports/dast/zap-report.json",
]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def seal_run_evidence(root: Path, incident_id: str,
                      scanners_dir: str = "reports/scanners") -> Dict[str, Any]:
    """Build and seal a manifest of this run's real evidence.

    Returns a dict with the real root_sha256/root_sha512, the per-file manifest,
    and the manifest path. Raises nothing for missing optional files; it only
    seals what actually exists.
    """
    root = Path(root)
    files: List[Dict[str, Any]] = []
    candidates = list(EVIDENCE_CANDIDATES)
    sdir = root / scanners_dir
    if sdir.is_dir():
        candidates += [f"{scanners_dir}/{p.name}" for p in sorted(sdir.glob("*.json"))]

    for rel in candidates:
        p = root / rel
        if p.is_file():
            files.append({"path": rel, "sha256": _sha256_file(p), "bytes": p.stat().st_size})

    manifest = {
        "incident_id": incident_id,
        "sealed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "file_count": len(files),
        "files": files,
    }
    # Canonical bytes -> real root digests. Any change to any sealed file (its
    # sha256 in the manifest) changes these roots.
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    root_sha256 = hashlib.sha256(canonical).hexdigest()
    root_sha512 = hashlib.sha512(canonical).hexdigest()

    manifest_out = manifest | {"root_sha256": root_sha256, "root_sha512": root_sha512}
    manifest_path = root / "reports" / "evidence-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest_out, indent=2) + "\n", encoding="utf-8")

    return {
        "incident_id": incident_id,
        "root_sha256": root_sha256,
        "root_sha512": root_sha512,
        "manifest_path": str(manifest_path.relative_to(root)),
        "manifest_bytes": len(canonical),
        "files": files,
        "file_count": len(files),
    }
