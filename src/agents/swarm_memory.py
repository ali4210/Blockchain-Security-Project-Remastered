#!/usr/bin/env python3
"""
Phase 3a: real RAG (retrieval-augmented generation) memory for
swarm_orchestrator.py's 7-agent swarm.

STORAGE CHOICE: a plain sqlite3 table (data/swarm_memory.db), not chromadb.
At this project's real data volume -- a handful of real pipeline runs so
far, not millions of vectors -- a full ANN vector-store dependency buys
nothing: cosine similarity over a few dozen stored vectors is a trivial
O(N) Python loop. sqlite3 is already stdlib (zero new dependency), and
matches this repo's existing data/forensics.db / data/threat_intel.db
convention (see src/forensics/evidence_db.py).

EMBEDDING AVAILABILITY (verified live, not assumed): the configured Ollama
host (OLLAMA_BASE_URL/OLLAMA_HOST) currently has no embedding-capable model
pulled (only qwen2.5-coder/deepseek-r1/qwen3.5/qwen3 chat models), AND the
running server instance itself was started without embeddings support --
/api/embed and /api/embeddings both return
{"error":"This server does not support embeddings. Start it with
`--embeddings`"} regardless of model. Enabling this for real would need,
on that host: `ollama pull nomic-embed-text` (~274MB, 137M params, 768-dim
-- the standard lightweight choice for this use case) and restarting the
Ollama server with embeddings enabled.

HONEST DEGRADE, NO EXCEPTIONS: every public function here returns a real
status alongside its result and never raises out to the caller. If no
embedding model is reachable, if the store has no embedded rows yet, or if
the embedding call fails for any other reason, retrieve_similar() returns
an empty context and says exactly why -- never a fabricated retrieved
example, never a silent failure that looks like retrieval happened when it
didn't.

DESIGN DECISION (same-contract history is NOT excluded): a past run on the
exact same contract (same source) is a legitimate, useful retrieval result
-- "we scanned this exact contract before and decided X" is real SOC
memory, not circular reasoning, especially for this project's small set of
repeatedly-rescanned fixture contracts. What IS structurally impossible
(by the write-after-read ordering in run_swarm(), never by a special-case
filter here) is a run retrieving its own not-yet-written record.
"""
import hashlib
import json
import math
import os
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "swarm_memory.db"

OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", os.getenv("OLLAMA_HOST", "http://192.168.0.189:11434"))
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
EMBED_TIMEOUT = int(os.getenv("OLLAMA_EMBED_TIMEOUT", "30"))

# Real current contracts are all <= ~5.2KB (VulnerableVault.sol, the
# largest, is 5156 bytes) -- 6000 gives real headroom without being an
# arbitrary round number disconnected from this repo's actual fixtures.
SOURCE_EXCERPT_LIMIT = 6000
TOP_K = int(os.getenv("SWARM_RAG_TOP_K", "3"))


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS swarm_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contract_name TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,
            source_excerpt TEXT NOT NULL,
            source_truncated INTEGER NOT NULL,
            findings_block TEXT NOT NULL,
            decision TEXT NOT NULL,
            embedding_json TEXT,
            embedding_model TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    return conn


def _embedding_text(contract_source: str, findings_block: str) -> str:
    """Same text representation used both when embedding a run for storage
    and when embedding the current run's retrieval query -- comparing
    anything else would make the cosine similarity meaningless."""
    return f"{contract_source}\n\nFINDINGS:\n{findings_block}"


def get_embedding(text: str) -> Tuple[Optional[List[float]], Optional[str]]:
    """Real call to Ollama's /api/embed. Returns (vector, None) on success,
    or (None, real_error_detail) on any failure -- never raises."""
    body = json.dumps({"model": EMBED_MODEL, "input": text}).encode()
    req = urllib.request.Request(f"{OLLAMA_BASE.rstrip('/')}/api/embed", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=EMBED_TIMEOUT) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as exc:
        # Ollama's real reason (e.g. "model 'x' not found", or "This server
        # does not support embeddings") is in the response BODY, not in
        # str(exc) -- urllib's default stringification ("HTTP Error 404:
        # Not Found") would otherwise hide the actually useful detail.
        try:
            body = json.loads(exc.read().decode("utf-8", errors="replace"))
            reason = body.get("error", str(exc))
        except (ValueError, UnicodeDecodeError):
            reason = str(exc)
        return None, f"ollama embedding call failed (HTTP {exc.code}): {str(reason)[:150]}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, f"ollama embedding host unreachable: {str(exc)[:150]}"
    except (ValueError, json.JSONDecodeError) as exc:
        return None, f"unparseable ollama embedding response: {str(exc)[:150]}"

    embeddings = data.get("embeddings")
    if not embeddings or not isinstance(embeddings, list) or not embeddings[0]:
        error_msg = data.get("error")
        detail = (f"ollama embedding call returned no vector: {error_msg}" if error_msg
                  else f"ollama embedding response had no 'embeddings' (keys: {sorted(data.keys())})")
        return None, detail
    return embeddings[0], None


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def record_run(contract_name: str, contract_source: str, findings_block: str, decision: str) -> Dict[str, Any]:
    """Stores one real, genuinely completed swarm run. Caller is responsible
    for only calling this once a real quorum of agents actually voted --
    never for a not_run/partial run (see run_swarm()'s status=="ok" gate).

    An embedding failure does NOT block storing the real run data itself
    (contract/findings/decision are real and worth keeping regardless);
    embedding_json simply stays NULL and retrieve_similar() skips such rows
    until a real embedding model is available and this run is re-recorded.
    """
    source_truncated = len(contract_source) > SOURCE_EXCERPT_LIMIT
    excerpt = contract_source[:SOURCE_EXCERPT_LIMIT]
    vector, embed_error = get_embedding(_embedding_text(contract_source, findings_block))

    try:
        conn = _connect()
        with conn:
            conn.execute(
                "INSERT INTO swarm_runs (contract_name, source_sha256, source_excerpt, "
                "source_truncated, findings_block, decision, embedding_json, embedding_model, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (contract_name, hashlib.sha256(contract_source.encode()).hexdigest(), excerpt,
                 int(source_truncated), findings_block, decision,
                 json.dumps(vector) if vector is not None else None,
                 EMBED_MODEL if vector is not None else None,
                 datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
        conn.close()
    except sqlite3.Error as exc:
        return {"status": "error", "detail": f"sqlite write failed: {str(exc)[:200]}"}

    if vector is None:
        return {"status": "stored_without_embedding", "detail": embed_error}
    return {"status": "ok", "detail": f"stored with {EMBED_MODEL} embedding ({len(vector)} dims)"}


def retrieve_similar(contract_source: str, findings_block: str, k: int = TOP_K) -> Tuple[str, Dict[str, Any]]:
    """Real retrieval. Returns (context_block, status). context_block is ""
    whenever nothing was genuinely retrieved -- the caller must build the
    prompt exactly as it does without RAG in that case, never fabricating
    an example."""
    query_vector, embed_error = get_embedding(_embedding_text(contract_source, findings_block))
    if query_vector is None:
        return "", {"status": "disabled_no_embedding", "detail": embed_error, "retrieved_count": 0}

    try:
        conn = _connect()
        rows = conn.execute(
            "SELECT contract_name, source_excerpt, findings_block, decision, embedding_json "
            "FROM swarm_runs WHERE embedding_json IS NOT NULL AND embedding_model = ?",
            (EMBED_MODEL,),
        ).fetchall()
        conn.close()
    except sqlite3.Error as exc:
        return "", {"status": "error", "detail": f"sqlite read failed: {str(exc)[:200]}", "retrieved_count": 0}

    if not rows:
        return "", {"status": "disabled_store_empty", "detail": "no past embedded runs stored yet",
                    "retrieved_count": 0}

    scored = []
    for row in rows:
        try:
            vec = json.loads(row["embedding_json"])
        except (ValueError, TypeError):
            continue
        scored.append((_cosine_similarity(query_vector, vec), row))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    top = scored[:k]

    if not top:
        return "", {"status": "disabled_store_empty", "detail": "no comparable embedded runs stored yet",
                    "retrieved_count": 0}

    lines = ["PAST SIMILAR CASES FROM THIS PIPELINE'S OWN REAL HISTORY "
            "(for calibration only -- decide THIS contract on its own merits):"]
    for score, row in top:
        lines.append(
            f"- Similar past case (contract: {row['contract_name']}, similarity: {score:.3f}): "
            f"findings were [{row['findings_block'][:200]}] -> swarm decided: {row['decision']}"
        )
    context = "\n".join(lines)
    return context, {"status": "ok", "detail": f"retrieved {len(top)} real past case(s)",
                     "retrieved_count": len(top)}
