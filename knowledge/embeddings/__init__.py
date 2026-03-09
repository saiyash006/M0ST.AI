"""
Embedding store for the Knowledge layer.

Stores and retrieves vector embeddings (GNN graph embeddings,
function embeddings, etc.) for similarity search and downstream
analysis tasks.
"""

import json
from typing import Any, Dict, List, Optional, Tuple


class EmbeddingStore:
    """In-memory store for function and graph embeddings."""

    def __init__(self):
        self._embeddings: Dict[str, Dict[str, Any]] = {}

    def store(self, key: str, vector: List[float], metadata: Optional[Dict] = None):
        self._embeddings[key] = {
            "key": key,
            "vector": vector,
            "dim": len(vector),
            "metadata": metadata or {},
        }

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        return self._embeddings.get(key)

    def search_similar(self, query_vector: List[float], top_k: int = 5) -> List[Tuple[str, float]]:
        """Brute-force cosine similarity search."""
        if not self._embeddings:
            return []

        results = []
        for key, entry in self._embeddings.items():
            score = self._cosine_similarity(query_vector, entry["vector"])
            results.append((key, score))
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def list_keys(self) -> List[str]:
        return sorted(self._embeddings.keys())

    def clear(self):
        self._embeddings.clear()

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        if len(a) != len(b) or not a:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x * x for x in a) ** 0.5
        norm_b = sum(x * x for x in b) ** 0.5
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)
