"""Real tests for src/agents/swarm_memory.py (Phase 3a RAG memory).

get_embedding is patched at its OWN module's attribute
(src.agents.swarm_memory.get_embedding) -- record_run/retrieve_similar call
it as a bare name within this same module, so this is the correct patch
site (not the Phase-1-style bug of patching a different module's copy of
an imported name). Every test uses an isolated sqlite file via monkeypatch
on DB_PATH, never the real data/swarm_memory.db.
"""
import json
import sqlite3
from unittest.mock import patch

import pytest

from src.agents import swarm_memory


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test_swarm_memory.db"
    monkeypatch.setattr(swarm_memory, "DB_PATH", db_path)
    return db_path


def _vec(*components):
    return list(components)


# ---- cosine similarity -----------------------------------------------------

def test_cosine_similarity_identical_vectors_is_one():
    assert swarm_memory._cosine_similarity(_vec(1, 0, 0), _vec(1, 0, 0)) == pytest.approx(1.0)


def test_cosine_similarity_orthogonal_vectors_is_zero():
    assert swarm_memory._cosine_similarity(_vec(1, 0), _vec(0, 1)) == pytest.approx(0.0)


def test_cosine_similarity_opposite_vectors_is_negative_one():
    assert swarm_memory._cosine_similarity(_vec(1, 0), _vec(-1, 0)) == pytest.approx(-1.0)


def test_cosine_similarity_zero_vector_does_not_crash():
    assert swarm_memory._cosine_similarity(_vec(0, 0), _vec(1, 1)) == 0.0


def test_cosine_similarity_mismatched_length_is_zero():
    assert swarm_memory._cosine_similarity(_vec(1, 0), _vec(1, 0, 0)) == 0.0


# ---- record_run -------------------------------------------------------------

def test_record_run_stores_real_row_with_embedding(isolated_db):
    with patch.object(swarm_memory, "get_embedding", return_value=([0.1, 0.2, 0.3], None)):
        result = swarm_memory.record_run("Vault.sol", "contract Vault {}", "- finding A", "HALT_CONFIRMED")
    assert result["status"] == "ok"

    conn = sqlite3.connect(str(isolated_db))
    rows = conn.execute("SELECT contract_name, decision, embedding_json, embedding_model FROM swarm_runs").fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][0] == "Vault.sol"
    assert rows[0][1] == "HALT_CONFIRMED"
    assert json.loads(rows[0][2]) == [0.1, 0.2, 0.3]
    assert rows[0][3] == swarm_memory.EMBED_MODEL


def test_record_run_stores_row_without_embedding_when_embed_fails(isolated_db):
    with patch.object(swarm_memory, "get_embedding", return_value=(None, "ollama embedding host unreachable: x")):
        result = swarm_memory.record_run("Vault.sol", "contract Vault {}", "- finding A", "CLEAR")
    assert result["status"] == "stored_without_embedding"
    assert "unreachable" in result["detail"]

    conn = sqlite3.connect(str(isolated_db))
    rows = conn.execute("SELECT embedding_json, embedding_model FROM swarm_runs").fetchall()
    conn.close()
    assert len(rows) == 1  # the real run data is still stored
    assert rows[0][0] is None
    assert rows[0][1] is None


def test_record_run_truncates_long_source(isolated_db):
    long_source = "x" * (swarm_memory.SOURCE_EXCERPT_LIMIT + 500)
    with patch.object(swarm_memory, "get_embedding", return_value=([0.1], None)):
        swarm_memory.record_run("Big.sol", long_source, "- f", "CLEAR")

    conn = sqlite3.connect(str(isolated_db))
    row = conn.execute("SELECT source_excerpt, source_truncated FROM swarm_runs").fetchone()
    conn.close()
    assert len(row[0]) == swarm_memory.SOURCE_EXCERPT_LIMIT
    assert row[1] == 1


# ---- retrieve_similar: honest-degrade paths --------------------------------

def test_retrieve_similar_disabled_when_no_embedding_model(isolated_db):
    with patch.object(swarm_memory, "get_embedding",
                      return_value=(None, "ollama embedding call returned no vector: this server does not support embeddings")):
        context, status = swarm_memory.retrieve_similar("contract X {}", "- finding")
    assert context == ""
    assert status["status"] == "disabled_no_embedding"
    assert status["retrieved_count"] == 0


def test_retrieve_similar_disabled_when_store_empty(isolated_db):
    with patch.object(swarm_memory, "get_embedding", return_value=([0.1, 0.2], None)):
        context, status = swarm_memory.retrieve_similar("contract X {}", "- finding")
    assert context == ""
    assert status["status"] == "disabled_store_empty"


def test_retrieve_similar_skips_rows_without_embedding(isolated_db):
    # One row stored without an embedding (embed failed at write time) --
    # must not be treated as a retrievable, comparable record.
    with patch.object(swarm_memory, "get_embedding", return_value=(None, "no embeddings")):
        swarm_memory.record_run("Old.sol", "contract Old {}", "- f", "CLEAR")
    with patch.object(swarm_memory, "get_embedding", return_value=([1.0, 0.0], None)):
        context, status = swarm_memory.retrieve_similar("contract X {}", "- finding")
    assert context == ""
    assert status["status"] == "disabled_store_empty"


# ---- retrieve_similar: real top-k ordering ---------------------------------

def test_retrieve_similar_returns_correct_top_k_ordering(isolated_db):
    # Three past runs with orthogonal-ish embeddings, varying similarity to
    # a query vector of [1, 0, 0].
    vectors = {
        "Closest.sol": [0.99, 0.1, 0.0],
        "Middle.sol": [0.5, 0.5, 0.0],
        "Farthest.sol": [0.0, 0.0, 1.0],
    }
    for name, vec in vectors.items():
        with patch.object(swarm_memory, "get_embedding", return_value=(vec, None)):
            swarm_memory.record_run(name, f"contract {name} {{}}", "- f", "CLEAR")

    with patch.object(swarm_memory, "get_embedding", return_value=([1.0, 0.0, 0.0], None)):
        context, status = swarm_memory.retrieve_similar("contract Query {}", "- finding", k=2)

    assert status["status"] == "ok"
    assert status["retrieved_count"] == 2
    # Closest must be ranked first, Middle second; Farthest excluded (k=2).
    closest_pos = context.find("Closest.sol")
    middle_pos = context.find("Middle.sol")
    assert closest_pos != -1 and middle_pos != -1
    assert closest_pos < middle_pos
    assert "Farthest.sol" not in context
    assert "swarm decided: CLEAR" in context


def test_retrieve_similar_allows_same_contract_as_past_history(isolated_db):
    """Deliberate design decision (see module docstring): a past run on the
    exact same contract is NOT excluded from retrieval."""
    with patch.object(swarm_memory, "get_embedding", return_value=([1.0, 0.0], None)):
        swarm_memory.record_run("VulnerableVault.sol", "contract VulnerableVault {}", "- reentrancy", "HALT_CONFIRMED")
    with patch.object(swarm_memory, "get_embedding", return_value=([1.0, 0.0], None)):
        context, status = swarm_memory.retrieve_similar("contract VulnerableVault {}", "- reentrancy")
    assert status["status"] == "ok"
    assert "VulnerableVault.sol" in context


def test_retrieve_similar_ignores_rows_from_a_different_embedding_model(isolated_db, monkeypatch):
    with patch.object(swarm_memory, "get_embedding", return_value=([1.0, 0.0], None)):
        swarm_memory.record_run("Old.sol", "contract Old {}", "- f", "CLEAR")
    monkeypatch.setattr(swarm_memory, "EMBED_MODEL", "a-different-embed-model")
    with patch.object(swarm_memory, "get_embedding", return_value=([1.0, 0.0], None)):
        context, status = swarm_memory.retrieve_similar("contract X {}", "- finding")
    assert context == ""
    assert status["status"] == "disabled_store_empty"
