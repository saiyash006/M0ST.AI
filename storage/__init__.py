# storage - graph store, SQLite, and snapshot management
from storage.memory_graph_store import MemoryGraphStore
from storage.sqlite_store import SQLiteStore
from storage.snapshots import SnapshotManager


def create_graph_store(**kwargs):
    """Create and return an in-memory graph store."""
    return MemoryGraphStore()


__all__ = [
    "MemoryGraphStore",
    "create_graph_store",
    "SQLiteStore",
    "SnapshotManager",
]
