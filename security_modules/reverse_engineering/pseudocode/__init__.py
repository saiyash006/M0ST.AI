"""
Pseudocode Generation module — Interfaces with decompilers.

Wraps Ghidra headless and radare2 decompilation backends to
produce normalized pseudocode from binary functions.
"""

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Optional

from core.config import get_config

try:
    import r2pipe
    _R2_AVAILABLE = True
except ImportError:
    _R2_AVAILABLE = False


class PseudocodeGenerator:
    """
    Generates pseudocode from binary functions using
    Ghidra headless or radare2 decompilation.
    """

    def __init__(self):
        config = get_config()
        self._ghidra_path = config.get("tools", {}).get("ghidra_path")
        self._r2_path = config.get("tools", {}).get("r2_path")

    def decompile(
        self,
        binary_path: str,
        func_addr: int,
    ) -> Dict[str, Any]:
        """
        Attempt decompilation via Ghidra, then r2 pdg, then r2 pdc.

        Returns dict with keys: pseudocode, normalized, source, variables, calls.
        """
        # Try Ghidra first
        if self._ghidra_path and os.path.exists(self._ghidra_path):
            result = self._decompile_ghidra(binary_path, func_addr)
            if result:
                return result

        # Try r2
        if _R2_AVAILABLE:
            result = self._decompile_r2(binary_path, func_addr)
            if result:
                return result

        return {
            "pseudocode": "",
            "normalized": "",
            "source": "none",
            "variables": [],
            "calls": [],
        }

    def _decompile_ghidra(
        self, binary_path: str, func_addr: int
    ) -> Optional[Dict[str, Any]]:
        """Attempt Ghidra headless decompilation."""
        if not self._ghidra_path:
            return None

        analyze_headless = os.path.join(self._ghidra_path, "support", "analyzeHeadless")
        if not os.path.isfile(analyze_headless):
            analyze_headless_bat = analyze_headless + ".bat"
            if os.path.isfile(analyze_headless_bat):
                analyze_headless = analyze_headless_bat
            else:
                return None

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                project_dir = os.path.join(tmpdir, "ghidra_project")
                os.makedirs(project_dir, exist_ok=True)
                output_file = os.path.join(tmpdir, "decompiled.c")

                cmd = [
                    analyze_headless,
                    project_dir,
                    "tmp_project",
                    "-import", binary_path,
                    "-postScript", "DecompileFunction.java",
                    f"0x{func_addr:x}",
                    output_file,
                    "-deleteProject",
                ]
                subprocess.run(
                    cmd, capture_output=True, timeout=120,
                    check=False,
                )

                if os.path.isfile(output_file):
                    with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                        code = f.read()
                    if code.strip():
                        normalized = self._normalize(code)
                        return {
                            "pseudocode": code,
                            "normalized": normalized,
                            "source": "ghidra",
                            "variables": self._extract_variables(normalized),
                            "calls": self._extract_calls(normalized),
                        }
        except Exception:
            pass
        return None

    def _decompile_r2(
        self, binary_path: str, func_addr: int
    ) -> Optional[Dict[str, Any]]:
        """Attempt r2 decompilation (pdg or pdc)."""
        flags = ["-2"]
        if self._r2_path:
            r2 = r2pipe.open(binary_path, flags=flags, radare2path=self._r2_path)
        else:
            r2 = r2pipe.open(binary_path, flags=flags)

        try:
            r2.cmd("aaa")
            r2.cmd(f"s 0x{func_addr:x}")

            # Try pdg (ghidra decompiler plugin for r2)
            code = r2.cmd("pdg")
            source = "r2_pdg"

            if not code or not code.strip() or "Cannot" in code:
                # Fall back to pdc
                code = r2.cmd("pdc")
                source = "r2_pdc"

            if code and code.strip():
                normalized = self._normalize(code)
                return {
                    "pseudocode": code,
                    "normalized": normalized,
                    "source": source,
                    "variables": self._extract_variables(normalized),
                    "calls": self._extract_calls(normalized),
                }
        except Exception:
            pass
        finally:
            r2.quit()

        return None

    def _normalize(self, code: str) -> str:
        """Normalize pseudocode for consistent formatting."""
        lines = code.splitlines()
        cleaned = []
        for line in lines:
            line = line.rstrip()
            # Remove radare2 address comments
            line = re.sub(r"//\s*0x[0-9a-fA-F]+", "", line)
            line = re.sub(r"/\*\s*0x[0-9a-fA-F]+\s*\*/", "", line)
            if line.strip():
                cleaned.append(line)
        return "\n".join(cleaned)

    def _extract_variables(self, code: str):
        """Extract variable names from pseudocode."""
        var_pattern = re.compile(
            r"\b(?:int|char|void|long|short|unsigned|uint\d+_t|int\d+_t|size_t|bool)\s+\*?\s*(\w+)",
        )
        return list(set(var_pattern.findall(code)))

    def _extract_calls(self, code: str):
        """Extract function call targets from pseudocode."""
        call_pattern = re.compile(r"\b(\w+)\s*\(")
        exclude = {"if", "while", "for", "switch", "return", "sizeof", "typeof"}
        calls = []
        for match in call_pattern.findall(code):
            if match not in exclude:
                calls.append(match)
        return list(set(calls))
