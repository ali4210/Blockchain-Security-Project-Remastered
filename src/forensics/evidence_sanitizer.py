"""
TODO(phase-10b): Evidence Sanitization Shield — evidence is untrusted input.
- Parse artifacts into structured fields with deterministic parsers first
- Mask long free-text fields: hash tag + length, raw text retrievable only
  by a human
- Wrap any remaining raw text as quoted data, not instructions
- Enforce per-artifact / per-call size caps (mirrors the Zone 2 AST caps)
See blueprint Section 4.8.
"""


def sanitize_artifact(_parsed_fields: dict) -> dict:
    raise NotImplementedError("not implemented — see checklist Phase 10b")


def mask_free_text(_text: str) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10b")
