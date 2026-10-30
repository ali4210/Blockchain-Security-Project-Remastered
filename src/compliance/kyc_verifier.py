"""Compliance KYC/AML name screening against a REAL OpenSanctions snapshot.

The matching engine (normalization, exact/alias lookup, fuzzy scoring) is
backed by a dated, hashed local snapshot of OpenSanctions' real Consolidated
Sanctions collection (government sanctions/PEP lists), produced out of band
by scripts/mirror-opensanctions.py (same offline-mirror pattern as
mirror-ofac.py/mirror-nvd.sh).

V1 SCOPE DECISION: sanctions/PEP *name* screening only. Full biometric KYC
(document OCR + liveness + face-match) was researched and deliberately
deferred -- document OCR (Tesseract/PassportEye) and face-match
(face_recognition/dlib) are genuinely open source, but robust liveness
detection has no clean open-source answer; real production-grade liveness is
proprietary/per-machine-licensed. Assembling an "open-source" biometric
pipeline without genuine liveness would be either incomplete/spoofable or
quietly dependent on a proprietary component, which violates this project's
explicit open-source-only requirement for this component. v2 TODO if that
changes.

LICENSE NOTE: OpenSanctions data is CC BY-NC 4.0 (non-commercial) -- see
scripts/mirror-opensanctions.py's docstring. This module and its snapshot are
built on that basis.

HONEST BEHAVIOUR (same contract as address_screener.py):
  * No snapshot, or a stale one -> OpenSanctionsSnapshotUnavailable is raised.
    Callers must translate that into a not_run result. A screen is NEVER
    silently returned as "clean" when the data source is missing.
  * A clean verdict (NO_MATCH) means the name was really checked against a
    present, current snapshot and not found above the inconclusive floor. It
    is a real result, not a failure dressed up as clean.
  * Tests inject their own records via snapshot_records= so they never depend
    on the live, changing OpenSanctions list.

HITL GOVERNANCE (same pattern as sar_generator.py): any CONFIRMED or
INCONCLUSIVE match produces a DraftKycReview, status DRAFT_PENDING_REVIEW,
requires_human_approval=True. This module never auto-blocks or auto-clears
anything on its own -- a human reviewer must act on the draft.
"""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from enum import Enum
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_SNAPSHOT_PATH = Path.home() / ".local/state/opensanctions-mirror/opensanctions-sanctions-snapshot.json"
DEFAULT_MAX_AGE_DAYS = 90  # OpenSanctions' sanctions collection is refreshed far
                           # less often than this project's own screening runs.

# Fuzzy-match thresholds (difflib.SequenceMatcher.ratio(), 0.0-1.0). Chosen
# empirically against the real snapshot: "LAZARUS" vs "LAZARUS GROUP" scores
# ~0.70 (a real partial/substring collision -- see judgment calls), so the
# inconclusive floor sits below that, and the confirm ceiling sits high enough
# that only near-exact/typo-level variants auto-confirm.
MATCH_THRESHOLD = 0.92
INCONCLUSIVE_THRESHOLD = 0.65

_WS_RE = re.compile(r"\s+")
_PUNCT_RE = re.compile(r"[^\w\s]")


class OpenSanctionsSnapshotUnavailable(RuntimeError):
    """The OpenSanctions snapshot is missing or too old to be trusted.
    Screening must report not_run rather than guess a clean result."""


class MatchConfidence(str, Enum):
    CONFIRMED = "CONFIRMED"        # exact name/alias hit, or near-exact fuzzy score
    INCONCLUSIVE = "INCONCLUSIVE"  # partial/ambiguous fuzzy score -- needs a human
    NO_MATCH = "NO_MATCH"


class KycReviewStatus(str, Enum):
    DRAFT_PENDING_REVIEW = "DRAFT_PENDING_REVIEW"
    CLEARED_FALSE_POSITIVE = "CLEARED_FALSE_POSITIVE"
    CONFIRMED_ESCALATE = "CONFIRMED_ESCALATE"


@dataclass(frozen=True)
class SanctionedEntity:
    entity_id: str
    schema: str            # "Person" | "Organization" | "Company" | ...
    name: str
    aliases: List[str]
    countries: List[str]
    sanctions: str
    program_ids: List[str]
    dataset: str


@dataclass(frozen=True)
class KycMatch:
    is_flagged: bool
    confidence: MatchConfidence
    score: float
    queried_name: str
    matched_entity: Optional[SanctionedEntity] = None
    matched_on: Optional[str] = None  # which name/alias string actually matched
    reason: str = "Name not found in sanctions/PEP registry."


@dataclass(frozen=True)
class DraftKycReview:
    review_id: str
    created_at_utc: str
    status: KycReviewStatus
    queried_name: str
    confidence: MatchConfidence
    score: float
    matched_entity: Optional[Dict[str, Any]]
    narrative: str
    review_digest: str
    requires_human_approval: bool = True
    action_channel: str = "LOCAL_STAGING_ONLY"


def normalize_name(name: str) -> str:
    """Canonicalize a name for matching: uppercase, strip punctuation, collapse
    whitespace. Deliberately simple (no transliteration) -- it only needs to
    match this project's own snapshot's already-normalized name strings."""
    cleaned = _PUNCT_RE.sub(" ", (name or "").strip().upper())
    return _WS_RE.sub(" ", cleaned).strip()


class KycScreener:
    """Deterministic name screener backed by the OpenSanctions snapshot.

    snapshot_records: inject records directly (tests); each needs at least
      'id'/'schema'/'name', optional 'aliases'/'countries'/'sanctions'/
      'program_ids'/'dataset'.
    snapshot_path / max_age_days: where to load the real snapshot and how old
      it may be before it is refused.
    """

    def __init__(self, snapshot_records: Optional[List[Dict[str, Any]]] = None,
                 snapshot_path: Optional[Path] = None,
                 max_age_days: int = DEFAULT_MAX_AGE_DAYS,
                 match_threshold: float = MATCH_THRESHOLD,
                 inconclusive_threshold: float = INCONCLUSIVE_THRESHOLD):
        self.match_threshold = match_threshold
        self.inconclusive_threshold = inconclusive_threshold
        if snapshot_records is not None:
            self._records = snapshot_records
            self.snapshot_meta: Dict[str, Any] = {"source": "injected",
                                                   "entity_count": len(snapshot_records)}
        else:
            self._records, self.snapshot_meta = self._load_snapshot(
                Path(snapshot_path) if snapshot_path else DEFAULT_SNAPSHOT_PATH, max_age_days)
        # exact_index: normalized name/alias string -> SanctionedEntity (fast path)
        self._exact_index: Dict[str, SanctionedEntity] = {}
        # candidates: (normalized_string, entity) for every name/alias, for fuzzy scan
        self._candidates: List[tuple] = []
        self._entities: List[SanctionedEntity] = []
        self._load_registry()
        self.snapshot_hash = self._compute_snapshot_hash()

    @staticmethod
    def _load_snapshot(path: Path, max_age_days: int):
        if not path.is_file():
            raise OpenSanctionsSnapshotUnavailable(
                f"OpenSanctions snapshot not found at {path}; "
                f"run scripts/mirror-opensanctions.py to build it")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise OpenSanctionsSnapshotUnavailable(f"OpenSanctions snapshot at {path} is unreadable: {exc}")
        downloaded_at = data.get("downloaded_at")
        if downloaded_at:
            try:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(downloaded_at)
                if age.days > max_age_days:
                    raise OpenSanctionsSnapshotUnavailable(
                        f"OpenSanctions snapshot is stale ({age.days}d old > {max_age_days}d limit); "
                        f"re-run scripts/mirror-opensanctions.py")
            except ValueError:
                raise OpenSanctionsSnapshotUnavailable(
                    f"OpenSanctions snapshot has an invalid downloaded_at: {downloaded_at!r}")
        entries = data.get("entries")
        if not entries:
            raise OpenSanctionsSnapshotUnavailable(f"OpenSanctions snapshot at {path} contains no entries")
        meta = {k: data.get(k) for k in
                ("source", "source_dataset", "downloaded_at", "csv_sha256", "entity_count", "license")}
        return entries, meta

    def _load_registry(self) -> None:
        self._exact_index.clear()
        self._candidates.clear()
        self._entities.clear()
        for item in self._records:
            entity = SanctionedEntity(
                entity_id=item.get("id", ""),
                schema=item.get("schema", ""),
                name=item.get("name", "UNKNOWN"),
                aliases=list(item.get("aliases") or []),
                countries=list(item.get("countries") or []),
                sanctions=item.get("sanctions", ""),
                program_ids=list(item.get("program_ids") or []),
                dataset=item.get("dataset", ""),
            )
            self._entities.append(entity)
            for raw in [entity.name, *entity.aliases]:
                norm = normalize_name(raw)
                if not norm:
                    continue
                self._exact_index.setdefault(norm, entity)
                self._candidates.append((norm, raw, entity))

    def _compute_snapshot_hash(self) -> str:
        serialized = json.dumps(
            sorted(e.entity_id for e in self._entities), sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def screen(self, name: str) -> KycMatch:
        norm = normalize_name(name)
        exact = self._exact_index.get(norm)
        if exact:
            return KycMatch(
                is_flagged=True, confidence=MatchConfidence.CONFIRMED, score=1.0,
                queried_name=name, matched_entity=exact, matched_on=exact.name,
                reason=f"Exact match on sanctions/PEP list: {exact.name} "
                       f"({exact.sanctions or exact.dataset})")

        best_score, best_name, best_entity = 0.0, None, None
        matcher = SequenceMatcher(a=norm)
        for candidate_norm, candidate_raw, entity in self._candidates:
            matcher.set_seq2(candidate_norm)
            if matcher.quick_ratio() < best_score:
                continue  # cheap upper-bound reject before the exact ratio() scan
            score = matcher.ratio()
            if score > best_score:
                best_score, best_name, best_entity = score, candidate_raw, entity

        if best_score >= self.match_threshold:
            return KycMatch(
                is_flagged=True, confidence=MatchConfidence.CONFIRMED, score=best_score,
                queried_name=name, matched_entity=best_entity, matched_on=best_name,
                reason=f"Near-exact match ({best_score:.2f}) on sanctions/PEP list: "
                       f"{best_entity.name} (matched via {best_name!r})")
        if best_score >= self.inconclusive_threshold:
            return KycMatch(
                is_flagged=True, confidence=MatchConfidence.INCONCLUSIVE, score=best_score,
                queried_name=name, matched_entity=best_entity, matched_on=best_name,
                reason=f"Ambiguous partial match ({best_score:.2f}) against "
                       f"{best_entity.name} (matched via {best_name!r}); human review required "
                       f"to confirm or rule out")
        return KycMatch(
            is_flagged=False, confidence=MatchConfidence.NO_MATCH, score=best_score,
            queried_name=name,
            reason="Clean: not found in the OpenSanctions sanctions/PEP snapshot.")

    def screen_batch(self, names: List[str]) -> List[KycMatch]:
        return [self.screen(n) for n in names]

    def total_entities(self) -> int:
        return len(self._entities)


class KycReviewGenerator:
    """Deterministic HITL draft-review generator for flagged KYC matches,
    mirroring sar_generator.py's governance pattern: every draft starts
    DRAFT_PENDING_REVIEW and requires_human_approval=True. This generator
    never changes pipeline state or gates anything by itself -- it only
    produces a reviewable artifact for a human compliance officer."""

    @staticmethod
    def _compute_digest(payload: Dict[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def generate_draft(self, case_id: str, match: KycMatch,
                        created_at_override: Optional[str] = None) -> DraftKycReview:
        if match.confidence == MatchConfidence.NO_MATCH:
            raise ValueError("generate_draft() is only for flagged (CONFIRMED/INCONCLUSIVE) matches")

        timestamp = created_at_override or datetime.now(timezone.utc).isoformat()
        entity_payload = asdict(match.matched_entity) if match.matched_entity else None

        narrative_lines = [
            f"KYC/AML SANCTIONS SCREENING REVIEW [CASE REF: {case_id}]",
            f"Generated Timestamp: {timestamp}",
            f"Queried Name: {match.queried_name}",
            f"Confidence: {match.confidence.value}  Score: {match.score:.3f}",
            f"Reason: {match.reason}",
        ]
        if entity_payload:
            narrative_lines.append(
                f"Candidate Entity: {entity_payload['name']} "
                f"({entity_payload['schema']}, {', '.join(entity_payload['countries']) or 'country unknown'})")
        narrative_lines.append(
            "GOVERNANCE NOTICE: This artifact is an automated internal draft. "
            "No account action, filing, or pipeline gate follows automatically from it. "
            "A human compliance reviewer must confirm or clear this match."
        )
        narrative = "\n".join(narrative_lines)

        core_payload = {
            "case_id": case_id,
            "created_at_utc": timestamp,
            "queried_name": match.queried_name,
            "confidence": match.confidence.value,
            "score": match.score,
            "matched_entity": entity_payload,
            "narrative": narrative,
        }
        digest = self._compute_digest(core_payload)

        return DraftKycReview(
            review_id=f"KYC-REVIEW-{case_id}",
            created_at_utc=timestamp,
            status=KycReviewStatus.DRAFT_PENDING_REVIEW,
            queried_name=match.queried_name,
            confidence=match.confidence,
            score=match.score,
            matched_entity=entity_payload,
            narrative=narrative,
            review_digest=digest,
            requires_human_approval=True,
            action_channel="LOCAL_STAGING_ONLY",
        )

    @staticmethod
    def verify_draft_integrity(draft: DraftKycReview) -> bool:
        core_payload = {
            "case_id": draft.review_id.replace("KYC-REVIEW-", ""),
            "created_at_utc": draft.created_at_utc,
            "queried_name": draft.queried_name,
            "confidence": draft.confidence.value,
            "score": draft.score,
            "matched_entity": draft.matched_entity,
            "narrative": draft.narrative,
        }
        computed = KycReviewGenerator._compute_digest(core_payload)
        return computed == draft.review_digest
