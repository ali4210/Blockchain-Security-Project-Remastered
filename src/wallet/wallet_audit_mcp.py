"""
Task P12-008: Wallet-Audit MCP Tool Registry.
Exposes Model Context Protocol (MCP) inspection tool with wallet-specific
static analysis rules (signature replay, ecrecover zero-address, delegatecall hijacking).
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set


class RateLimitExceededError(Exception):
    """Raised when an agent client exceeds the MCP call rate limit."""
    pass


@dataclass(frozen=True)
class WalletAuditFinding:
    rule_id: str
    severity: str
    title: str
    description: str
    pattern_matched: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TokenBucketRateLimiter:
    """Token bucket rate limiter for MCP endpoints."""

    def __init__(self, capacity: int = 10, refill_rate: float = 2.0):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill_rate = refill_rate
        self.last_update = time.monotonic()

    def consume(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_update
        self.last_update = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


def _strip_solidity_comments(source: str) -> str:
    """Removes single-line and multi-line comments so comments do not alter AST/regex checks."""
    no_block = re.sub(r"/\*[\s\S]*?\*/", "", source)
    return re.sub(r"//.*", "", no_block)


class WalletAuditRuleEngine:
    """Evaluates wallet source code against specialized static analysis rules."""

    @classmethod
    def scan_source(cls, raw_source_code: str) -> List[WalletAuditFinding]:
        findings: List[WalletAuditFinding] = []
        code = _strip_solidity_comments(raw_source_code)

        # RULE-WLT-001: Signature Replay / Missing Nonce Tracking
        has_sig_recovery = bool(re.search(r"\b(ecrecover|ECDSA\.recover)\b", code))
        has_nonce_tracking = bool(re.search(r"\b(nonces?(\[|\+\+|\+=)|nonce\s*\+\+|nonce\s*=\s*nonce\s*\+\s*1)\b", code, re.IGNORECASE))
        if has_sig_recovery and not has_nonce_tracking:
            findings.append(
                WalletAuditFinding(
                    rule_id="RULE-WLT-001",
                    severity="CRITICAL",
                    title="Signature Replay / Missing Nonce Tracking",
                    description="Signature verification detected without monotonic nonce tracking or replay prevention.",
                    pattern_matched="ecrecover without nonce state increment",
                    remediation="Bind signatures to monotonic nonces and EIP-712 domain separators.",
                )
            )

        # RULE-WLT-002: Unvalidated Zero-Address ecrecover Return
        has_raw_ecrecover = bool(re.search(r"\becrecover\s*\(", code))
        has_zero_check = bool(re.search(r"!=\s*address\(0\)|address\(0\)\s*!=", code))
        if has_raw_ecrecover and not has_zero_check:
            findings.append(
                WalletAuditFinding(
                    rule_id="RULE-WLT-002",
                    severity="CRITICAL",
                    title="Unvalidated Zero-Address ecrecover Return",
                    description="ecrecover return address used without explicit address(0) validation check.",
                    pattern_matched="ecrecover(...) without != address(0)",
                    remediation="Always require recovered != address(0) to prevent unauthenticated signature bypass.",
                )
            )

        # RULE-WLT-003: Arbitrary Delegatecall Hijacking
        delegate_match = re.search(r"\.delegatecall\s*\(", code)
        if delegate_match:
            findings.append(
                WalletAuditFinding(
                    rule_id="RULE-WLT-003",
                    severity="CRITICAL",
                    title="Arbitrary Delegatecall Hijacking",
                    description="Wallet execution function permits arbitrary delegatecall target execution.",
                    pattern_matched=delegate_match.group(0),
                    remediation="Restrict delegatecall to immutable authorized implementation logic or safe module allowlist.",
                )
            )

        # RULE-WLT-004: Missing Reentrancy Protection in Multi-Send
        multi_match = re.search(r"function\s+(multiSend|executeBatch)\b", code)
        if multi_match and "nonReentrant" not in code:
            findings.append(
                WalletAuditFinding(
                    rule_id="RULE-WLT-004",
                    severity="WARNING",
                    title="Missing Reentrancy Protection in Multi-Send",
                    description="Batch execution function lacks nonReentrant modifier or CEI sequencing.",
                    pattern_matched=multi_match.group(0),
                    remediation="Apply nonReentrant modifier and adhere strictly to checks-effects-interactions pattern.",
                )
            )

        # RULE-WLT-005: Raw ecrecover Malleability (Low-s omission)
        if has_raw_ecrecover and not bool(re.search(r"s\s*<=\s*0x7FFFFFFF|s\s*<=\s*_N", code)):
            findings.append(
                WalletAuditFinding(
                    rule_id="RULE-WLT-005",
                    severity="WARNING",
                    title="Malleable Signature low-s Check Omission",
                    description="Raw ecrecover without BIP-146 / OpenZeppelin ECDSA canonical low-s validation.",
                    pattern_matched="raw ecrecover call",
                    remediation="Use OpenZeppelin ECDSA.recover() or explicitly enforce s <= secp256k1n / 2.",
                )
            )

        return findings


class WalletAuditMcpRegistry:
    """
    Model Context Protocol registry exposing the wallet audit tool interface.
    """

    def __init__(self, rate_limiter: Optional[TokenBucketRateLimiter] = None):
        self._rate_limiter = rate_limiter or TokenBucketRateLimiter(capacity=10, refill_rate=2.0)
        self._tools: Dict[str, Dict[str, Any]] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        self.register_tool(
            name="audit_wallet_contract",
            description="Performs specialized static security analysis on multisig and smart wallet contract source code.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "contract_source": {
                        "type": "string",
                        "description": "Solidity source code of the wallet contract to audit.",
                    },
                    "contract_name": {
                        "type": "string",
                        "description": "Optional name of the target contract.",
                        "default": "WalletContract",
                    },
                },
                "required": ["contract_source"],
            },
            handler=self._handle_audit_wallet_contract,
        )

    def register_tool(
        self,
        name: str,
        description: str,
        parameters_schema: Dict[str, Any],
        handler: Callable[[Dict[str, Any]], Dict[str, Any]],
    ) -> None:
        self._tools[name] = {
            "name": name,
            "description": description,
            "parameters_schema": parameters_schema,
            "handler": handler,
        }

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": t["name"],
                "description": t["description"],
                "parameters_schema": t["parameters_schema"],
            }
            for t in self._tools.values()
        ]

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not self._rate_limiter.consume(1.0):
            raise RateLimitExceededError(f"Rate limit exceeded on MCP tool '{tool_name}'.")

        if tool_name not in self._tools:
            raise ValueError(f"Unknown MCP tool '{tool_name}'. Available: {list(self._tools.keys())}")

        return self._tools[tool_name]["handler"](arguments)

    def _handle_audit_wallet_contract(self, args: Dict[str, Any]) -> Dict[str, Any]:
        source = args.get("contract_source", "")
        contract_name = args.get("contract_name", "WalletContract")

        if not source or not isinstance(source, str):
            raise ValueError("Parameter 'contract_source' must be a non-empty string.")

        findings = WalletAuditRuleEngine.scan_source(source)
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")

        return {
            "contract_name": contract_name,
            "findings": [f.to_dict() for f in findings],
            "finding_count": len(findings),
            "critical_count": critical_count,
            "requires_quarantine": critical_count > 0,
            "scanned_at": datetime.now(timezone.utc).timestamp(),
        }
