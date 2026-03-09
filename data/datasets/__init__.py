"""
Dataset pipeline — collects training data from analysis runs for fine-tuning
GNN and LLM models (Step 9 of M0ST architecture).
"""

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


class DatasetPipeline:
    """
    Collects and curates datasets from analysis runs for model training.

    Supported dataset types:
      - function_embeddings: CFG embedding vectors paired with function metadata
      - vulnerability_labels: labeled vulnerability data for supervised training
      - symbol_recovery: function name / variable name ground-truth pairs
      - deobfuscation: obfuscated ↔ deobfuscated function pairs
    """

    def __init__(self, datasets_dir: str = "data/datasets"):
        self._datasets_dir = datasets_dir
        self._datasets: Dict[str, List[Dict[str, Any]]] = {
            "function_embeddings": [],
            "vulnerability_labels": [],
            "symbol_recovery": [],
            "deobfuscation": [],
        }

    # ── Embedding dataset ────────────────────────────────────────────

    def add_embedding_sample(
        self,
        binary_sha256: str,
        function_name: str,
        embedding: List[float],
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Record a function embedding sample for training."""
        self._datasets["function_embeddings"].append({
            "binary": binary_sha256,
            "function": function_name,
            "embedding": embedding,
            "metadata": metadata or {},
            "timestamp": time.time(),
        })

    # ── Vulnerability dataset ────────────────────────────────────────

    def add_vulnerability_label(
        self,
        binary_sha256: str,
        function_name: str,
        vuln_type: str,
        severity: str,
        features: Optional[Dict[str, Any]] = None,
    ):
        """Record a labeled vulnerability for supervised training."""
        self._datasets["vulnerability_labels"].append({
            "binary": binary_sha256,
            "function": function_name,
            "vuln_type": vuln_type,
            "severity": severity,
            "features": features or {},
            "timestamp": time.time(),
        })

    # ── Symbol recovery dataset ──────────────────────────────────────

    def add_symbol_ground_truth(
        self,
        binary_sha256: str,
        address: str,
        predicted_name: str,
        ground_truth_name: str,
        correct: bool,
    ):
        """Record a symbol recovery prediction vs ground truth."""
        self._datasets["symbol_recovery"].append({
            "binary": binary_sha256,
            "address": address,
            "predicted": predicted_name,
            "ground_truth": ground_truth_name,
            "correct": correct,
            "timestamp": time.time(),
        })

    # ── Deobfuscation dataset ────────────────────────────────────────

    def add_deobfuscation_pair(
        self,
        binary_sha256: str,
        function_name: str,
        obfuscated_cfg: Dict[str, Any],
        simplified_cfg: Dict[str, Any],
        techniques_found: List[str],
    ):
        """Record an obfuscated ↔ simplified function pair."""
        self._datasets["deobfuscation"].append({
            "binary": binary_sha256,
            "function": function_name,
            "obfuscated": obfuscated_cfg,
            "simplified": simplified_cfg,
            "techniques": techniques_found,
            "timestamp": time.time(),
        })

    # ── Query & export ───────────────────────────────────────────────

    def get_dataset(self, name: str) -> List[Dict[str, Any]]:
        """Get all samples for a dataset type."""
        return self._datasets.get(name, [])

    def dataset_stats(self) -> Dict[str, int]:
        """Return sample counts per dataset type."""
        return {name: len(samples) for name, samples in self._datasets.items()}

    def export_dataset(self, name: str, output_path: Optional[str] = None) -> str:
        """Export a dataset to JSON. Returns the JSON string."""
        samples = self._datasets.get(name, [])
        data = json.dumps(samples, indent=2, default=str)
        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w") as f:
                f.write(data)
        return data

    def clear_dataset(self, name: Optional[str] = None):
        """Clear a specific dataset or all datasets."""
        if name:
            self._datasets[name] = []
        else:
            for key in self._datasets:
                self._datasets[key] = []
