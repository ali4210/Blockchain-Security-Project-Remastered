"""
Swarm State Schema (Phase 5 — Zone 4).
Decoupled state container to prevent circular imports across agent nodes.
"""

from typing import Any, Dict, List, Optional


class SwarmState(dict):
    """
    Standard state payload propagated across the sequential agent graph.
    """
    def __init__(
        self,
        target_contract: str = "",
        findings: Optional[List[Dict[str, Any]]] = None,
        current_stage: str = "INITIAL",
        escalation_needed: bool = False,
        errors: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        super().__init__(
            target_contract=target_contract,
            findings=findings or [],
            current_stage=current_stage,
            escalation_needed=escalation_needed,
            errors=errors or [],
            metadata=metadata or {},
            **kwargs,
        )
