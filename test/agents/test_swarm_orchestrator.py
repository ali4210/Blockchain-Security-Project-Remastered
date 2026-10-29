"""Real tests for src/agents/swarm_orchestrator.py's Phase 3a RAG wiring.

retrieve_similar/record_run are patched at src.agents.swarm_orchestrator's
OWN names (it does `from src.agents.swarm_memory import record_run,
retrieve_similar`, binding its own local references at import time) --
patching src.agents.swarm_memory's copies would be the exact Phase-1 bug
this project already found and fixed once. call_ollama is defined in and
called from this same module, so patching
src.agents.swarm_orchestrator.call_ollama is the correct, non-buggy target
for it.
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.agents import swarm_orchestrator as so


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    contract = tmp_path / "Vault.sol"
    contract.write_text("contract Vault { function withdraw() external {} }")
    monkeypatch.setenv("TARGET_CONTRACT", str(contract))
    monkeypatch.setattr(so, "ROOT", tmp_path)
    monkeypatch.setattr(so, "SAST_REPORT", tmp_path / "reports" / "sast-symbolic-report.json")
    return tmp_path, contract


def ok_vote(agent, agent_id, vote="HALT"):
    return {"agent": agent, "agent_id": agent_id, "model": "qwen3.5:9b", "status": "ok",
            "vote": vote, "reason": "test", "raw": f"VERDICT: {vote} | REASON: test"}


def fake_call_ollama_factory(votes_by_agent_id, captured_states):
    def fake_call_ollama(role, agent_id, state):
        captured_states.append(dict(state))
        return ok_vote(role, agent_id, votes_by_agent_id.get(agent_id, "HALT"))
    return fake_call_ollama


# ---- _prompt(): honest-degrade byte-identical, and real inclusion ---------

ORIGINAL_PROMPT_TEMPLATE = (
    "You are the {role} agent in an automated smart-contract security SOC.\n"
    "Decide whether deploying this contract must HALT (an exploitable HIGH or "
    "CRITICAL risk exists) or is CLEAR (no exploitable high/critical risk).\n\n"
    "CONTRACT: {contract_name}\n"
    "```solidity\n{contract_source}\n```\n\n"
    "STATIC + SYMBOLIC FINDINGS (Slither + Mythril):\n{findings_block}\n\n"
    "Respond with EXACTLY one line, nothing else:\n"
    "VERDICT: HALT | REASON: <one short sentence>\n"
    "or\n"
    "VERDICT: CLEAR | REASON: <one short sentence>"
)


def test_prompt_byte_identical_to_pre_rag_version_when_context_empty():
    state = {"contract_name": "Vault.sol", "contract_source": "contract Vault {}",
             "findings_block": "- reentrancy-eth", "retrieval_context": ""}
    actual = so._prompt("Auditor (Agent A)", state)
    expected = ORIGINAL_PROMPT_TEMPLATE.format(
        role="Auditor (Agent A)", contract_name="Vault.sol",
        contract_source="contract Vault {}", findings_block="- reentrancy-eth")
    assert actual == expected


def test_prompt_includes_retrieval_context_when_present():
    state = {"contract_name": "Vault.sol", "contract_source": "contract Vault {}",
             "findings_block": "- reentrancy-eth",
             "retrieval_context": "- Similar past case: Old.sol -> swarm decided: HALT_CONFIRMED"}
    actual = so._prompt("Auditor (Agent A)", state)
    assert "Similar past case: Old.sol -> swarm decided: HALT_CONFIRMED" in actual
    # Still contains the strict output-format instruction, unmodified.
    assert actual.endswith("VERDICT: CLEAR | REASON: <one short sentence>")


def test_prompt_missing_retrieval_context_key_degrades_safely():
    """.get() usage means an older-shaped state (no RAG at all) must not crash."""
    state = {"contract_name": "Vault.sol", "contract_source": "contract Vault {}",
             "findings_block": "- f"}
    actual = so._prompt("Auditor (Agent A)", state)
    expected = ORIGINAL_PROMPT_TEMPLATE.format(
        role="Auditor (Agent A)", contract_name="Vault.sol",
        contract_source="contract Vault {}", findings_block="- f")
    assert actual == expected


# ---- run_swarm(): real wiring, ordering, and gating ------------------------

def test_run_swarm_retrieves_before_voting_and_records_after(isolated_env):
    tmp_path, contract = isolated_env
    call_log = []

    def fake_retrieve(source, findings_block, k=3):
        call_log.append("retrieve")
        return "- Similar past case: Old.sol -> swarm decided: HALT_CONFIRMED", {
            "status": "ok", "detail": "retrieved 1 real past case(s)", "retrieved_count": 1}

    def fake_record(name, source, findings_block, decision):
        call_log.append("record")
        return {"status": "ok", "detail": "stored"}

    captured_states = []

    def fake_call_ollama(role, agent_id, state):
        call_log.append(f"vote-{agent_id}")
        captured_states.append(dict(state))
        return ok_vote(role, agent_id, "HALT")

    with patch.object(so, "retrieve_similar", side_effect=fake_retrieve), \
         patch.object(so, "record_run", side_effect=fake_record), \
         patch.object(so, "call_ollama", side_effect=fake_call_ollama):
        report = so.run_swarm()

    # Real ordering: retrieval happens once, strictly before all 7 votes,
    # and the store write happens strictly after all votes complete.
    assert call_log[0] == "retrieve"
    assert call_log[-1] == "record"
    assert call_log[1:-1] == [f"vote-{aid}" for aid in ("A", "B", "C", "D", "E", "F", "G")]

    # Every agent's prompt-building state carried the SAME retrieved context
    # from this run's single retrieval call -- never re-embedded per agent,
    # never containing this run's own (not-yet-written) record.
    for state in captured_states:
        assert state["retrieval_context"] == ("- Similar past case: Old.sol -> "
                                               "swarm decided: HALT_CONFIRMED")
    assert report["rag"]["retrieval"]["status"] == "ok"
    assert report["rag"]["write"]["status"] == "ok"


def test_run_swarm_records_only_when_quorum_voted(isolated_env):
    tmp_path, contract = isolated_env
    record_calls = []

    def fake_record(name, source, findings_block, decision):
        record_calls.append((name, decision))
        return {"status": "ok", "detail": "stored"}

    # 2 of 7 vote, 5 not_run -> below quorum -> status "error" -> must NOT record.
    def fake_call_ollama_partial(role, agent_id, state):
        if agent_id in ("A", "B"):
            return ok_vote(role, agent_id, "HALT")
        return {"agent": role, "agent_id": agent_id, "model": "qwen3.5:9b", "status": "not_run",
                "vote": "ABSTAIN", "reason": "ollama unreachable", "raw": ""}

    with patch.object(so, "retrieve_similar", return_value=("", {"status": "disabled_store_empty",
                                                                 "detail": "empty", "retrieved_count": 0})), \
         patch.object(so, "record_run", side_effect=fake_record), \
         patch.object(so, "call_ollama", side_effect=fake_call_ollama_partial):
        report = so.run_swarm()

    assert report["rag"]["write"] is None
    assert record_calls == []


def test_run_swarm_does_not_record_when_fully_not_run(isolated_env):
    tmp_path, contract = isolated_env
    record_calls = []

    def fake_record(*a, **k):
        record_calls.append(a)
        return {"status": "ok"}

    def fake_call_ollama_unreachable(role, agent_id, state):
        return {"agent": role, "agent_id": agent_id, "model": "qwen3.5:9b", "status": "not_run",
                "vote": "ABSTAIN", "reason": "ollama unreachable", "raw": ""}

    with patch.object(so, "retrieve_similar", return_value=("", {"status": "disabled_no_embedding",
                                                                 "detail": "no model", "retrieved_count": 0})), \
         patch.object(so, "record_run", side_effect=fake_record), \
         patch.object(so, "call_ollama", side_effect=fake_call_ollama_unreachable):
        report = so.run_swarm()

    assert report["rag"]["write"] is None
    assert record_calls == []


def test_run_swarm_records_real_completed_run_with_correct_args(isolated_env):
    tmp_path, contract = isolated_env
    record_calls = []

    def fake_record(name, source, findings_block, decision):
        record_calls.append({"name": name, "source": source, "findings_block": findings_block,
                             "decision": decision})
        return {"status": "ok", "detail": "stored"}

    def fake_call_ollama_all_halt(role, agent_id, state):
        return ok_vote(role, agent_id, "HALT")

    with patch.object(so, "retrieve_similar", return_value=("", {"status": "disabled_store_empty",
                                                                 "detail": "empty", "retrieved_count": 0})), \
         patch.object(so, "record_run", side_effect=fake_record), \
         patch.object(so, "call_ollama", side_effect=fake_call_ollama_all_halt):
        so.run_swarm()

    assert len(record_calls) == 1
    assert record_calls[0]["name"] == "Vault.sol"
    assert record_calls[0]["source"] == contract.read_text()
    assert record_calls[0]["decision"] == "HALT_CONFIRMED"


def test_run_swarm_report_reflects_honest_degrade_when_no_embedding(isolated_env):
    tmp_path, contract = isolated_env

    def fake_call_ollama_all_halt(role, agent_id, state):
        return ok_vote(role, agent_id, "HALT")

    with patch.object(so, "retrieve_similar",
                      return_value=("", {"status": "disabled_no_embedding",
                                        "detail": "ollama embedding call returned no vector: "
                                                  "this server does not support embeddings",
                                        "retrieved_count": 0})), \
         patch.object(so, "record_run", return_value={"status": "stored_without_embedding",
                                                       "detail": "no embedding"}), \
         patch.object(so, "call_ollama", side_effect=fake_call_ollama_all_halt):
        report = so.run_swarm()

    assert report["rag"]["retrieval"]["status"] == "disabled_no_embedding"
    assert report["rag"]["write"]["status"] == "stored_without_embedding"
    # Honest degrade must not have blocked the real swarm vote itself.
    assert report["decision"] == "HALT_CONFIRMED"
