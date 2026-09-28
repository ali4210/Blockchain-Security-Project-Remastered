"""
TODO(phase-5): Agent-Aware Router — Transport Bridge to the Windows GPU host.
This is the skeleton; the full working version is specified in Blueprint
V10.1 Section 6 — port that logic in during Phase 5. It includes fixes on
top of the original V10.0 appendix code:
  - per-agent context windows (AGENT_NUM_CTX: A=32K, B=16K, C=8K, D=16K,
    E=8K, F=32K, G=32K)
  - Agent G's 300s deterministic timeout cap
  - a real keep_alive purge (purge_model() / agent_stage() context manager) —
    the V10.0 client never sent keep_alive, so the purge never actually fired
  - mTLS client cert + Bearer token support (see Section 7 note 2 for the
    Ollama-has-no-native-mTLS workaround: reverse proxy in front of Ollama)
"""
from typing import Dict, List, Literal, Optional, Union

AgentType = Literal["A", "B", "C", "D", "E", "F", "G"]

AGENT_MODEL_ROUTING: Dict[AgentType, str] = {
    # TODO(phase-5): fill in per blueprint Section 6 table (Agent -> model)
}

AGENT_NUM_CTX: Dict[AgentType, int] = {
    # TODO(phase-5): A=32768, B=16384, C=8192, D=16384, E=8192, F=32768, G=32768
}


def chat(messages: List[Dict[str, str]], model: Optional[str] = None,
         force_agent: Optional[AgentType] = None,
         keep_alive: Optional[Union[int, str]] = None) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 5")


def purge_model(_model: str) -> None:
    """Ephemeral VRAM Lifecycle Engine: unload a model immediately (keep_alive: 0)."""
    raise NotImplementedError("not implemented — see checklist Phase 5")


def agent_stage(_agent: AgentType):
    """Context manager: purge the model when an agent stage ends."""
    raise NotImplementedError("not implemented — see checklist Phase 5")
