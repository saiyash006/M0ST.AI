"""
Analysis results storage — persists outputs from analysis runs.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional


class AnalysisResultStore:
    """
    Stores and retrieves analysis results keyed by binary hash + analysis type.
    """

    def __init__(self, results_dir: str = "data/results"):
        self._results_dir = results_dir
        self._results: Dict[str, List[Dict[str, Any]]] = {}

    def store(self, binary_sha256: str, analysis_type: str, result: Dict[str, Any]):
        """Store an analysis result for a binary."""
        key = f"{binary_sha256}:{analysis_type}"
        entry = {
            "binary_sha256": binary_sha256,
            "analysis_type": analysis_type,
            "timestamp": time.time(),
            "data": result,
        }
        self._results.setdefault(key, []).append(entry)

    def get_latest(self, binary_sha256: str, analysis_type: str) -> Optional[Dict[str, Any]]:
        """Get the most recent result for a binary + analysis type."""
        key = f"{binary_sha256}:{analysis_type}"
        entries = self._results.get(key, [])
        return entries[-1] if entries else None

    def get_all(self, binary_sha256: str) -> List[Dict[str, Any]]:
        """Get all results for a binary."""
        results = []
        for key, entries in self._results.items():
            if key.startswith(binary_sha256 + ":"):
                results.extend(entries)
        return sorted(results, key=lambda e: e["timestamp"])

    def list_types(self, binary_sha256: str) -> List[str]:
        """List analysis types completed for a binary."""
        types = []
        for key in self._results:
            if key.startswith(binary_sha256 + ":"):
                types.append(key.split(":", 1)[1])
        return types

    def export_json(self, binary_sha256: str) -> str:
        """Export all results for a binary as JSON."""
        return json.dumps(self.get_all(binary_sha256), indent=2, default=str)

    def clear(self, binary_sha256: Optional[str] = None):
        """Clear results for a specific binary, or all results."""
        if binary_sha256:
            keys_to_remove = [k for k in self._results if k.startswith(binary_sha256 + ":")]
            for k in keys_to_remove:
                del self._results[k]
        else:
            self._results.clear()
