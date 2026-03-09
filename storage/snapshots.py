from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.capabilities import Capability
from storage.sqlite_store import SQLiteStore


class SnapshotManager:
    """
    Stores analysis metadata snapshots in SQLite as JSON blobs.
    Graph data is not snapshotted here.
    """

    CAPABILITIES = {Capability.SNAPSHOT}

    def __init__(self, sqlite_store: SQLiteStore, graph_store=None):
        self.store = sqlite_store
        self.graph_store = graph_store

    def create_snapshot(self, name: str, description: str):
        timestamp = datetime.now(timezone.utc).isoformat()

        metadata: Dict[str, Any] = {
            "timestamp": timestamp,
            "description": description,
            "binary_path": None,
            "run_id": None,
            "function_count": None,
            "verification_state": None,
            "semantic_summaries": {},
        }

        if self.graph_store is not None:
            try:
                latest_run = self.graph_store.get_latest_run()
                if latest_run:
                    metadata["binary_path"] = latest_run.get("binary_path")
                    metadata["run_id"] = latest_run.get("id")
            except Exception:
                pass
            try:
                metadata["function_count"] = len(self.graph_store.fetch_functions())
            except Exception:
                metadata["function_count"] = None
            try:
                metadata["verification_state"] = self.graph_store.get_verification_results()
            except Exception:
                metadata["verification_state"] = None
            try:
                metadata["semantic_summaries"] = self.graph_store.get_semantic_summaries() or {}
            except Exception:
                metadata["semantic_summaries"] = {}

        self.store.save_snapshot(name, timestamp, metadata, files=[])

    def load_snapshot(self, name: str) -> Optional[Dict]:
        return self.store.load_snapshot(name)

    def list_snapshots(self) -> List[Dict]:
        return self.store.list_snapshots()

    def diff_snapshots(self, a: str, b: str) -> Dict:
        snap_a = self.store.load_snapshot(a)
        snap_b = self.store.load_snapshot(b)
        if snap_a is None or snap_b is None:
            return {
                "error": "snapshot_not_found",
                "missing": [n for n, s in [(a, snap_a), (b, snap_b)] if s is None],
            }

        meta_a = snap_a.get("metadata", {})
        meta_b = snap_b.get("metadata", {})
        diffs = {}
        for key in sorted(set(meta_a.keys()) | set(meta_b.keys())):
            if meta_a.get(key) != meta_b.get(key):
                diffs[key] = {"a": meta_a.get(key), "b": meta_b.get(key)}

        return {"a": a, "b": b, "diffs": diffs}
