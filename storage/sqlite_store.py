import json
import os
import sqlite3
from typing import Dict, List, Optional

from core.config import get_config


class SQLiteStore:
    """
    Stores metadata, logs, snapshots, and plugin registry.
    Responsibilities:
    - Keep stable tabular data separate from graph structures.
    - Provide historical versioned snapshots.
    - Track agent runs, errors, and cached results.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = get_config().get("sqlite", {}).get("db_path", "storage/metadata.db")
        # Resolve relative paths against the project root
        if not os.path.isabs(db_path):
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(project_root, db_path)
        # Ensure directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    name TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT,
                    files_json TEXT
                )
                """
            )
            # M0ST: function_ai_insights
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS function_ai_insights (
                    func_addr INTEGER PRIMARY KEY,
                    func_name TEXT,
                    suggested_name TEXT,
                    summary TEXT,
                    types_json TEXT,
                    variables_json TEXT,
                    vulnerabilities_json TEXT,
                    algorithmic_intent TEXT,
                    confidence REAL,
                    updated_at TEXT
                )
                """
            )
            # M0ST: cfg_embeddings
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cfg_embeddings (
                    func_addr INTEGER PRIMARY KEY,
                    embedding_json TEXT,
                    embedding_dim INTEGER,
                    model_arch TEXT,
                    updated_at TEXT
                )
                """
            )
            # M0ST: llm_results_cache
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_results_cache (
                    cache_key TEXT PRIMARY KEY,
                    func_addr INTEGER,
                    task TEXT,
                    prompt_hash TEXT,
                    result_json TEXT,
                    provider TEXT,
                    model TEXT,
                    created_at TEXT
                )
                """
            )

    def save_snapshot(self, name: str, created_at: str, metadata: Dict, files: List[Dict]):
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO snapshots (name, created_at, metadata_json, files_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    name,
                    created_at,
                    json.dumps(metadata or {}),
                    json.dumps(files or []),
                ),
            )

    def load_snapshot(self, name: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT name, created_at, metadata_json, files_json FROM snapshots WHERE name = ?",
                (name,),
            ).fetchone()
            if row is None:
                return None
            return {
                "name": row[0],
                "created_at": row[1],
                "metadata": json.loads(row[2]) if row[2] else {},
                "files": json.loads(row[3]) if row[3] else [],
            }

    def list_snapshots(self) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT name, created_at FROM snapshots ORDER BY created_at"
            ).fetchall()
        return [{"name": r[0], "created_at": r[1]} for r in rows]

    # ── AI Insights ────────────────────────────────────────────────────────

    def save_ai_insight(self, func_addr: int, insight: Dict):
        """Save AI-generated insight for a function."""
        from datetime import datetime, timezone

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO function_ai_insights
                (func_addr, func_name, suggested_name, summary, types_json,
                 variables_json, vulnerabilities_json, algorithmic_intent,
                 confidence, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    func_addr,
                    insight.get("func_name", ""),
                    insight.get("suggested_name", ""),
                    insight.get("summary", ""),
                    json.dumps(insight.get("types", {})),
                    json.dumps(insight.get("variables", [])),
                    json.dumps(insight.get("vulnerabilities", [])),
                    insight.get("algorithmic_intent", ""),
                    insight.get("confidence", 0.0),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def load_ai_insight(self, func_addr: int) -> Optional[Dict]:
        """Load AI insight for a function."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM function_ai_insights WHERE func_addr = ?",
                (func_addr,),
            ).fetchone()
            if row is None:
                return None
            return {
                "func_addr": row[0],
                "func_name": row[1],
                "suggested_name": row[2],
                "summary": row[3],
                "types": json.loads(row[4]) if row[4] else {},
                "variables": json.loads(row[5]) if row[5] else [],
                "vulnerabilities": json.loads(row[6]) if row[6] else [],
                "algorithmic_intent": row[7],
                "confidence": row[8],
                "updated_at": row[9],
            }

    def list_ai_insights(self) -> List[Dict]:
        """List all stored AI insights."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT func_addr, func_name, suggested_name, confidence, updated_at "
                "FROM function_ai_insights ORDER BY func_addr"
            ).fetchall()
        return [
            {
                "func_addr": r[0],
                "func_name": r[1],
                "suggested_name": r[2],
                "confidence": r[3],
                "updated_at": r[4],
            }
            for r in rows
        ]

    # ── CFG Embeddings ─────────────────────────────────────────────────────

    def save_cfg_embedding(self, func_addr: int, embedding: List[float], model_arch: str = "gat"):
        """Save GNN embedding for a function's CFG."""
        from datetime import datetime, timezone

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cfg_embeddings
                (func_addr, embedding_json, embedding_dim, model_arch, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    func_addr,
                    json.dumps(embedding),
                    len(embedding),
                    model_arch,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def load_cfg_embedding(self, func_addr: int) -> Optional[Dict]:
        """Load GNN embedding for a function."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT func_addr, embedding_json, embedding_dim, model_arch, updated_at "
                "FROM cfg_embeddings WHERE func_addr = ?",
                (func_addr,),
            ).fetchone()
            if row is None:
                return None
            return {
                "func_addr": row[0],
                "embedding": json.loads(row[1]) if row[1] else [],
                "embedding_dim": row[2],
                "model_arch": row[3],
                "updated_at": row[4],
            }

    # ── LLM Results Cache ─────────────────────────────────────────────────

    def cache_llm_result(
        self,
        cache_key: str,
        func_addr: int,
        task: str,
        prompt_hash: str,
        result: Dict,
        provider: str = "",
        model: str = "",
    ):
        """Cache an LLM inference result."""
        from datetime import datetime, timezone

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO llm_results_cache
                (cache_key, func_addr, task, prompt_hash, result_json, provider, model, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cache_key,
                    func_addr,
                    task,
                    prompt_hash,
                    json.dumps(result),
                    provider,
                    model,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def get_cached_llm_result(self, cache_key: str) -> Optional[Dict]:
        """Retrieve a cached LLM result."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT result_json, created_at FROM llm_results_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
            if row is None:
                return None
            return {
                "result": json.loads(row[0]) if row[0] else {},
                "created_at": row[1],
            }
