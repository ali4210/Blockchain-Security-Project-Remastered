"""
Task P10B-002: Deterministic Evidence Sanitizer.
Sanitizes raw evidence artifacts before LLM agent consumption via structured parsing,
bounded size caps, deterministic free-text masking, and data-only framing.
"""

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Dict, List, Union

MAX_ARTIFACT_BYTES = 512 * 1024  # 512 KB
MAX_RECURSION_DEPTH = 8
MAX_FREE_TEXT_LEN = 64

# Patterns indicative of prompt injection, instruction overrides, or jailbreaks
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an)\s+", re.IGNORECASE),
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"override\s+policy", re.IGNORECASE),
    re.compile(r"disregard\s+guardrails", re.IGNORECASE),
]


def mask_string(text: str) -> str:
    """Masks a sensitive or prompt-bearing string into a deterministic metadata token."""
    text_bytes = text.encode("utf-8")
    digest = hashlib.sha256(text_bytes).hexdigest()[:16]
    return f"<MASKED_PAYLOAD len={len(text)} sha256={digest}>"


class EvidenceSanitizer:
    """Deterministic sanitizer for forensic data consumed by autonomous AI agents."""

    def __init__(
        self,
        max_bytes: int = MAX_ARTIFACT_BYTES,
        max_depth: int = MAX_RECURSION_DEPTH,
        text_threshold: int = MAX_FREE_TEXT_LEN,
    ):
        self.max_bytes = max_bytes
        self.max_depth = max_depth
        self.text_threshold = text_threshold

    def _should_mask(self, text: str) -> bool:
        """Determines if a string contains injection patterns or exceeds text thresholds."""
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(text):
                return True
        return len(text) > self.text_threshold

    def _sanitize_value(self, value: Any, current_depth: int) -> Any:
        """Recursively sanitizes values while preserving deterministic data structure."""
        if current_depth > self.max_depth:
            return "<RECURSION_DEPTH_EXCEEDED>"

        if isinstance(value, str):
            if self._should_mask(value):
                return mask_string(value)
            return value

        if isinstance(value, (int, float, bool)) or value is None:
            return value

        if isinstance(value, list):
            return [self._sanitize_value(item, current_depth + 1) for item in value]

        if isinstance(value, dict):
            # Sort keys deterministically
            sanitized_dict = {}
            for k in sorted(value.keys()):
                # Clean key names to alphanumeric + underscores
                safe_key = re.sub(r"[^\w\-.]", "_", str(k))
                sanitized_dict[safe_key] = self._sanitize_value(value[k], current_depth + 1)
            return sanitized_dict

        # Fallback for unexpected types: stringify and evaluate
        return self._sanitize_value(str(value), current_depth)

    def sanitize_payload(self, raw_data: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
        """Applies deterministic parsing, masking, and data-only framing."""
        # 1. Size bounds check
        if isinstance(raw_data, bytes):
            if len(raw_data) > self.max_bytes:
                raise ValueError(f"Artifact exceeds maximum size cap: {len(raw_data)} > {self.max_bytes} bytes")
            try:
                parsed_data = json.loads(raw_data.decode("utf-8"))
            except Exception:
                # If non-JSON text/binary, frame as masked raw record
                parsed_data = {"raw_content": raw_data.decode("utf-8", errors="replace")}
        elif isinstance(raw_data, str):
            raw_bytes = raw_data.encode("utf-8")
            if len(raw_bytes) > self.max_bytes:
                raise ValueError(f"Artifact exceeds maximum size cap: {len(raw_bytes)} > {self.max_bytes} bytes")
            try:
                parsed_data = json.loads(raw_data)
            except Exception:
                parsed_data = {"raw_content": raw_data}
        elif isinstance(raw_data, dict):
            serialized = json.dumps(raw_data).encode("utf-8")
            if len(serialized) > self.max_bytes:
                raise ValueError(f"Artifact exceeds maximum size cap: {len(serialized)} > {self.max_bytes} bytes")
            parsed_data = raw_data
        else:
            raise TypeError(f"Unsupported evidence payload type: {type(raw_data)}")

        # 2. Recursive sanitization
        sanitized_content = self._sanitize_value(parsed_data, current_depth=0)

        # 3. Data-only framing wrapper
        return {
            "data_type": "sanitized_evidence",
            "framing": "DATA_ONLY_NO_EXECUTION",
            "sanitized_payload": sanitized_content,
        }
