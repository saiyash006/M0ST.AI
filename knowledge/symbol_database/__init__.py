"""
Symbol Database — stores recovered symbols (function names, variable names,
type information) produced by the symbol recovery pipeline.
"""

from typing import Any, Dict, List, Optional


class SymbolDatabase:
    """In-memory recovered symbol store."""

    def __init__(self):
        self._function_names: Dict[int, Dict[str, Any]] = {}
        self._variable_names: Dict[str, Dict[str, Any]] = {}
        self._type_info: Dict[str, Dict[str, Any]] = {}

    def add_function_name(self, addr: int, name: str, confidence: float = 0.0,
                          source: str = "unknown"):
        self._function_names[addr] = {
            "addr": addr,
            "name": name,
            "confidence": confidence,
            "source": source,
        }

    def get_function_name(self, addr: int) -> Optional[Dict[str, Any]]:
        return self._function_names.get(addr)

    def list_function_names(self) -> List[Dict[str, Any]]:
        return sorted(self._function_names.values(), key=lambda x: x["addr"])

    def add_variable_name(self, var_id: str, name: str, var_type: str = "unknown",
                          confidence: float = 0.0, source: str = "unknown"):
        self._variable_names[var_id] = {
            "id": var_id,
            "name": name,
            "type": var_type,
            "confidence": confidence,
            "source": source,
        }

    def get_variable_name(self, var_id: str) -> Optional[Dict[str, Any]]:
        return self._variable_names.get(var_id)

    def add_type_info(self, type_id: str, type_name: str, kind: str = "primitive",
                      fields: Optional[List] = None):
        self._type_info[type_id] = {
            "id": type_id,
            "name": type_name,
            "kind": kind,
            "fields": fields or [],
        }

    def get_type_info(self, type_id: str) -> Optional[Dict[str, Any]]:
        return self._type_info.get(type_id)

    def clear(self):
        self._function_names.clear()
        self._variable_names.clear()
        self._type_info.clear()
