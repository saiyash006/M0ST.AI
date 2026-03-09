import importlib.util
import os
import time
from typing import Dict, List, Optional

from core.capabilities import Capability


class PluginManager:
    """
    Dynamically loads analysis plugins from the plugins directory and its subdirectories.
    Each plugin must expose analyze(graph_store, func_addr) -> dict.

    Plugins can now operate through the PKG (Program Knowledge Graph) layer
    when a pkg instance is provided, falling back to direct graph_store access.
    """

    CAPABILITIES = {Capability.PLUGIN_ANALYSIS}

    def __init__(self, plugins_dir: Optional[str] = None, pkg=None):
        self.plugins_dir = plugins_dir or os.path.dirname(__file__)
        self._plugins: Dict[str, callable] = {}
        self._pkg = pkg  # Optional ProgramKnowledgeGraph instance

    def set_pkg(self, pkg):
        """Attach a ProgramKnowledgeGraph for PKG-routed plugin results."""
        self._pkg = pkg

    def load_plugins(self):
        self._plugins = {}
        self._scan_dir(self.plugins_dir)

    def _scan_dir(self, directory: str):
        """Recursively scan for plugin .py files."""
        if not os.path.isdir(directory):
            return
        for entry in os.listdir(directory):
            full_path = os.path.join(directory, entry)
            if os.path.isdir(full_path):
                # Skip __pycache__ and hidden dirs
                if entry.startswith("_") or entry.startswith("."):
                    continue
                self._scan_dir(full_path)
            elif entry.endswith(".py") and not entry.startswith("_"):
                self._load_plugin_file(full_path)

    def _load_plugin_file(self, path: str):
        filename = os.path.basename(path)
        module_name = f"plugin_{os.path.splitext(filename)[0]}_{int(time.time() * 1000)}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                return
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            analyze = getattr(module, "analyze", None)
            if callable(analyze):
                rel_name = os.path.relpath(path, self.plugins_dir)
                self._plugins[rel_name] = analyze
        except Exception as exc:
            print(f"[PluginManager] Failed to import {path}: {exc}")

    def list_plugins(self) -> List[str]:
        return sorted(self._plugins.keys())

    def run_all(self, graph_store, func_addr: int) -> Dict:
        facts: Dict = {}
        for name, analyze in self._plugins.items():
            try:
                result = analyze(graph_store, func_addr)
                if isinstance(result, dict):
                    facts.update(result)
            except Exception as exc:
                print(f"[PluginManager] Plugin {name} failed: {exc}")
                continue

        if facts:
            # Route through PKG when available, fall back to graph_store
            if self._pkg is not None:
                self._store_facts_via_pkg(func_addr, facts)
            else:
                graph_store.set_plugin_facts(func_addr, facts)
        return facts

    def _store_facts_via_pkg(self, func_addr: int, facts: Dict):
        """Store plugin results as annotations in the PKG."""
        addr_hex = hex(func_addr)
        for key, value in facts.items():
            self._pkg.annotate(addr_hex, f"plugin:{key}", value)
