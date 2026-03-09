import copy
import os
from typing import Any, Dict, Optional

import yaml
from core import load_env


DEFAULT_CONFIG: Dict[str, Any] = {
    "sqlite": {
        "db_path": "storage/metadata.db",
    },
    "tools": {
        "r2_path": "",
        "gdb_path": "",
        "ghidra_path": "",
    },
    "pipeline": {
        "event_timeout_seconds": 10.0,
    },
    "llm": {
        "provider": "none",
        "model": "",
        "api_key": "",
        "base_url": "",
        "temperature": 0.2,
        "max_tokens": 4096,
    },
    "gnn": {
        "model_path": "",
        "architecture": "gat",
        "hidden_dim": 128,
        "out_dim": 64,
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml_config(path: str = "config.yml") -> Dict[str, Any]:
    # Try given path, then relative to project root
    candidates = [path]
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(project_root, path))
    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                    return data if isinstance(data, dict) else {}
            except Exception:
                return {}
    return {}


def _apply_env_overrides(config: Dict[str, Any]) -> Dict[str, Any]:
    env_map = {
        "SQLITE_DB": ("sqlite", "db_path"),
        "R2_PATH": ("tools", "r2_path"),
        "GDB_PATH": ("tools", "gdb_path"),
        "GHIDRA_PATH": ("tools", "ghidra_path"),
        "PIPELINE_EVENT_TIMEOUT": ("pipeline", "event_timeout_seconds"),
        "LLM_PROVIDER": ("llm", "provider"),
        "LLM_MODEL": ("llm", "model"),
        "OPENAI_API_KEY": ("llm", "api_key"),
        "ANTHROPIC_API_KEY": ("llm", "api_key"),
        "MISTRAL_API_KEY": ("llm", "api_key"),
        "OPENROUTER_API_KEY": ("llm", "api_key"),
        "LLM_API_KEY": ("llm", "api_key"),  # generic override, highest priority
        "LLM_BASE_URL": ("llm", "base_url"),
        "GNN_MODEL_PATH": ("gnn", "model_path"),
    }

    out = copy.deepcopy(config)
    for env_name, path in env_map.items():
        raw = os.getenv(env_name)
        if raw is None:
            continue
        section, key = path
        value: Any = raw
        if (section, key) in {
            ("pipeline", "event_timeout_seconds"),
            ("llm", "temperature"),
        }:
            try:
                value = float(raw)
            except ValueError:
                continue
        out.setdefault(section, {})
        out[section][key] = value
    return out


_CONFIG_CACHE: Optional[Dict[str, Any]] = None


def get_config(path: str = "config.yml") -> Dict[str, Any]:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is None:
        load_env()
        file_config = _load_yaml_config(path)
        merged = _deep_merge(DEFAULT_CONFIG, file_config)
        _CONFIG_CACHE = _apply_env_overrides(merged)
    return _CONFIG_CACHE
