"""
Disassembly module — Wraps radare2 for binary disassembly.

Provides a clean interface for extracting functions, basic blocks,
instructions, and symbols from binaries via r2pipe.
"""

import os
import shutil
from typing import Any, Dict, List, Optional

from core.config import get_config

try:
    import r2pipe
    _R2_AVAILABLE = True
except ImportError:
    _R2_AVAILABLE = False


class Disassembler:
    """
    Radare2-based disassembler.

    Extracts function lists, instructions, strings, imports/exports,
    and sections from a given binary.
    """

    def __init__(self):
        config = get_config()
        self._r2_path = config.get("tools", {}).get("r2_path")

    def is_available(self) -> bool:
        if not _R2_AVAILABLE:
            return False
        r2_cmd = self._r2_path or "radare2"
        return shutil.which(r2_cmd) is not None

    def disassemble(self, binary_path: str) -> Dict[str, Any]:
        """
        Full disassembly of a binary.

        Returns dict with keys: functions, strings, imports, exports, sections, info.
        """
        if not self.is_available():
            return {"error": "radare2 not available"}

        if not os.path.isfile(binary_path):
            return {"error": f"Binary not found: {binary_path}"}

        flags = ["-2"]
        if self._r2_path:
            r2 = r2pipe.open(binary_path, flags=flags, radare2path=self._r2_path)
        else:
            r2 = r2pipe.open(binary_path, flags=flags)

        try:
            r2.cmd("aaa")

            functions = r2.cmdj("aflj") or []
            strings = r2.cmdj("izj") or []
            imports = r2.cmdj("iij") or []
            exports = r2.cmdj("iEj") or []
            sections = r2.cmdj("iSj") or []
            info = r2.cmdj("ij") or {}

            return {
                "functions": functions,
                "strings": strings,
                "imports": imports,
                "exports": exports,
                "sections": sections,
                "info": info,
            }
        finally:
            r2.quit()

    def disassemble_function(self, binary_path: str, func_addr: int) -> Dict[str, Any]:
        """Disassemble a single function by address."""
        if not self.is_available():
            return {"error": "radare2 not available"}

        flags = ["-2"]
        if self._r2_path:
            r2 = r2pipe.open(binary_path, flags=flags, radare2path=self._r2_path)
        else:
            r2 = r2pipe.open(binary_path, flags=flags)

        try:
            r2.cmd("aaa")
            r2.cmd(f"s 0x{func_addr:x}")

            blocks = r2.cmdj("afbj") or []
            disasm = r2.cmd("pdf")

            return {
                "addr": func_addr,
                "blocks": blocks,
                "disasm_text": disasm,
            }
        finally:
            r2.quit()

    def get_function_list(self, binary_path: str) -> List[Dict[str, Any]]:
        """Get list of functions from a binary."""
        result = self.disassemble(binary_path)
        return result.get("functions", [])
