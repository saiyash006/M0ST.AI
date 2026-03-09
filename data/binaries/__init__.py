"""
Binary data management — tracks analyzed binaries and their metadata.
"""

import hashlib
import os
from typing import Any, Dict, List, Optional


class BinaryRepository:
    """
    Manages binary files for analysis.
    Tracks metadata, hashes, and analysis state.
    """

    def __init__(self, storage_dir: str = "data/binary_store"):
        self._storage_dir = storage_dir
        self._registry: Dict[str, Dict[str, Any]] = {}

    def register(self, binary_path: str) -> Dict[str, Any]:
        """Register a binary for analysis and compute metadata."""
        if not os.path.isfile(binary_path):
            return {"error": f"File not found: {binary_path}"}

        file_hash = self._compute_sha256(binary_path)
        file_size = os.path.getsize(binary_path)
        file_name = os.path.basename(binary_path)

        entry = {
            "path": os.path.abspath(binary_path),
            "name": file_name,
            "sha256": file_hash,
            "size": file_size,
            "analyzed": False,
        }
        self._registry[file_hash] = entry
        return entry

    def get(self, sha256: str) -> Optional[Dict[str, Any]]:
        return self._registry.get(sha256)

    def list_all(self) -> List[Dict[str, Any]]:
        return list(self._registry.values())

    def mark_analyzed(self, sha256: str):
        if sha256 in self._registry:
            self._registry[sha256]["analyzed"] = True

    def _compute_sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
