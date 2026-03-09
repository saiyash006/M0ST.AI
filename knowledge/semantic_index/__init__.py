"""
Semantic Index — stores semantic metadata about recovered program entities.

Tracks high-level semantic labels, behavioral summaries, and algorithmic
intent associated with functions, blocks, and variables.
"""

from typing import Any, Dict, List, Optional


class SemanticIndex:
    """In-memory semantic metadata index."""

    def __init__(self):
        self._entries: Dict[str, Dict[str, Any]] = {}

    def add_entry(self, entity_id: str, summary: str = "",
                  behavior: str = "", intent: str = "",
                  tags: Optional[List[str]] = None, **props):
        self._entries[entity_id] = {
            "entity_id": entity_id,
            "summary": summary,
            "behavior": behavior,
            "intent": intent,
            "tags": tags or [],
            **props,
        }

    def get_entry(self, entity_id: str) -> Optional[Dict[str, Any]]:
        return self._entries.get(entity_id)

    def search_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        return [e for e in self._entries.values() if tag in e.get("tags", [])]

    def list_entries(self) -> List[Dict[str, Any]]:
        return list(self._entries.values())

    def clear(self):
        self._entries.clear()
