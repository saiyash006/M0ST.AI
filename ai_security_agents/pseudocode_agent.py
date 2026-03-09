"""
M0ST Pseudocode Agent — Extracts and normalizes decompiled pseudocode.

Uses Ghidra's headless decompiler or radare2's pdg/pdc commands to produce
C-like pseudocode, then normalizes and structures the output for downstream
LLM analysis.
"""

import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from core.capabilities import Capability

try:
    import r2pipe
    _R2_AVAILABLE = True
except ImportError:
    _R2_AVAILABLE = False


class PseudocodeAgent:
    """Pseudocode extraction and normalization agent."""

    CAPABILITIES = {Capability.PSEUDOCODE, Capability.STATIC_READ}

    def __init__(self, graph_store, ghidra_path: Optional[str] = None,
                 ghidra_project_dir: Optional[str] = None):
        self.g = graph_store
        self.ghidra_path = ghidra_path or os.environ.get("GHIDRA_PATH", "")
        self.ghidra_project_dir = ghidra_project_dir or tempfile.gettempdir()
        self._cache: Dict[int, Dict[str, Any]] = {}

    def decompile_function(self, func_addr: int,
                           binary_path: Optional[str] = None) -> Dict[str, Any]:
        if func_addr in self._cache:
            return self._cache[func_addr]

        result = None

        if binary_path and self.ghidra_path and os.path.isdir(self.ghidra_path):
            result = self._decompile_ghidra(func_addr, binary_path)

        if result is None and binary_path and _R2_AVAILABLE:
            result = self._decompile_r2_pdg(func_addr, binary_path)

        if result is None and binary_path and _R2_AVAILABLE:
            result = self._decompile_r2_pdc(func_addr, binary_path)

        if result is None:
            result = self._reconstruct_from_graph(func_addr)

        if result and result.get("pseudocode"):
            result["normalized"] = self._normalize_pseudocode(result["pseudocode"])
            result["variables"] = self._extract_variables(result["pseudocode"])
            result["calls"] = self._extract_calls(result["pseudocode"])
            result["has_loops"] = self._detect_loops(result["pseudocode"])
            result["has_branches"] = self._detect_branches(result["pseudocode"])

        self._cache[func_addr] = result
        return result

    def decompile_all(self, binary_path: Optional[str] = None) -> Dict[int, Dict[str, Any]]:
        results = {}
        for func in self.g.fetch_functions():
            addr = func.get("addr")
            if addr is None:
                continue
            results[addr] = self.decompile_function(addr, binary_path)
        return results

    def clear_cache(self):
        self._cache.clear()

    def _decompile_ghidra(self, func_addr: int, binary_path: str) -> Optional[Dict[str, Any]]:
        try:
            headless = os.path.join(self.ghidra_path, "support", "analyzeHeadless")
            if os.name == "nt":
                headless += ".bat"
            if not os.path.isfile(headless):
                return None

            script_content = f"""
import ghidra.app.decompiler.DecompInterface as DecompInterface
import ghidra.util.task.ConsoleTaskMonitor as ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

func = getFunctionAt(toAddr(0x{func_addr:x}))
if func is None:
    func = getFunctionContaining(toAddr(0x{func_addr:x}))

if func is not None:
    results = decompiler.decompileFunction(func, 60, monitor)
    if results.depiledFunction() is not None:
        print("__DECOMPILED_START__")
        print(results.getDecompiledFunction().getC())
        print("__DECOMPILED_END__")

decompiler.dispose()
"""
            script_file = os.path.join(tempfile.gettempdir(), "spider_decompile.py")
            with open(script_file, "w") as f:
                f.write(script_content)

            project_name = "spider_temp"
            cmd = [headless, self.ghidra_project_dir, project_name,
                   "-import", binary_path, "-postScript", script_file,
                   "-deleteProject", "-noanalysis"]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = proc.stdout
            start_marker = "__DECOMPILED_START__"
            end_marker = "__DECOMPILED_END__"

            if start_marker in output and end_marker in output:
                start = output.index(start_marker) + len(start_marker)
                end = output.index(end_marker)
                pseudocode = output[start:end].strip()
                return {
                    "func_addr": func_addr, "pseudocode": pseudocode, "normalized": "",
                    "source": "ghidra", "variables": [], "calls": [],
                    "has_loops": False, "has_branches": False,
                }
        except Exception as e:
            print(f"[PseudocodeAgent] Ghidra decompilation failed: {e}")
        return None

    def _decompile_r2_pdg(self, func_addr: int, binary_path: str) -> Optional[Dict[str, Any]]:
        r2 = None
        try:
            r2 = r2pipe.open(binary_path)
            r2.cmd("aaa")
            code = r2.cmd(f"pdg @ {func_addr}")
            if code and len(code.strip()) > 10 and "Cannot" not in code:
                return {
                    "func_addr": func_addr, "pseudocode": code.strip(), "normalized": "",
                    "source": "r2_pdg", "variables": [], "calls": [],
                    "has_loops": False, "has_branches": False,
                }
        except Exception:
            pass
        finally:
            if r2:
                try:
                    r2.quit()
                except Exception:
                    pass
        return None

    def _decompile_r2_pdc(self, func_addr: int, binary_path: str) -> Optional[Dict[str, Any]]:
        r2 = None
        try:
            r2 = r2pipe.open(binary_path)
            r2.cmd("aaa")
            code = r2.cmd(f"pdc @ {func_addr}")
            if code and len(code.strip()) > 10:
                return {
                    "func_addr": func_addr, "pseudocode": code.strip(), "normalized": "",
                    "source": "r2_pdc", "variables": [], "calls": [],
                    "has_loops": False, "has_branches": False,
                }
        except Exception:
            pass
        finally:
            if r2:
                try:
                    r2.quit()
                except Exception:
                    pass
        return None

    def _reconstruct_from_graph(self, func_addr: int) -> Dict[str, Any]:
        funcs = self.g.fetch_functions()
        func_name = f"sub_{func_addr:x}"
        for f in funcs:
            if f.get("addr") == func_addr:
                func_name = f.get("name", func_name)
                break

        blocks = self.g.fetch_basic_blocks(func_addr)
        edges = self.g.fetch_flow_edges(func_addr)

        if not blocks:
            return {
                "func_addr": func_addr,
                "pseudocode": f"// No blocks found for {func_name} @ 0x{func_addr:x}",
                "normalized": "", "source": "reconstructed", "variables": [],
                "calls": [], "has_loops": False, "has_branches": False,
            }

        succs = {}
        for s, d in edges:
            succs.setdefault(s, []).append(d)

        back_edges = set()
        for s, d in edges:
            if d <= s:
                back_edges.add((s, d))

        lines = [f"// Reconstructed pseudocode for {func_name} @ 0x{func_addr:x}"]
        lines.append(f"void {func_name}() {{")

        for bb in blocks:
            insns = self.g.fetch_block_instructions(bb)
            is_loop_target = any(d == bb for s, d in back_edges)
            if is_loop_target:
                lines.append(f"  // Loop header at 0x{bb:x}")
                lines.append(f"  loop_0x{bb:x}:")
            lines.append(f"  // Block 0x{bb:x} ({len(insns)} instructions)")
            for insn in insns:
                mnem = insn.get("mnemonic", "???")
                ops = insn.get("operands", [])
                ops_str = ", ".join(str(o) for o in ops)
                addr = insn.get("addr", 0)
                lines.append(f"    /* 0x{addr:x} */ {mnem} {ops_str};")
            bb_succs = succs.get(bb, [])
            if len(bb_succs) == 2:
                lines.append(f"    if (cond) goto 0x{bb_succs[0]:x}; else goto 0x{bb_succs[1]:x};")
            elif len(bb_succs) == 1:
                if (bb, bb_succs[0]) in back_edges:
                    lines.append(f"    goto loop_0x{bb_succs[0]:x}; // back-edge")
                else:
                    lines.append(f"    goto 0x{bb_succs[0]:x};")
        lines.append("}")

        pseudocode = "\n".join(lines)
        return {
            "func_addr": func_addr, "pseudocode": pseudocode, "normalized": "",
            "source": "reconstructed", "variables": [], "calls": [],
            "has_loops": bool(back_edges),
            "has_branches": any(len(succs.get(bb, [])) > 1 for bb in blocks),
        }

    def _normalize_pseudocode(self, code: str) -> str:
        code = re.sub(r"\n{3,}", "\n\n", code)
        code = re.sub(r"//\s*WARNING:.*\n", "", code)
        code = re.sub(r"/\*\s*WARNING:.*?\*/", "", code, flags=re.DOTALL)
        lines = []
        for line in code.split("\n"):
            stripped = line.rstrip()
            if stripped:
                lines.append(stripped)
            elif lines and lines[-1]:
                lines.append("")
        return "\n".join(lines)

    def _extract_variables(self, code: str) -> List[Dict[str, str]]:
        variables = []
        decl_pattern = re.compile(
            r"(?:int|char|void|long|short|unsigned|signed|float|double|uint\d+_t|int\d+_t|size_t|bool)\s*\*?\s*(\w+)"
        )
        for match in decl_pattern.finditer(code):
            name = match.group(1)
            if name not in ("if", "else", "while", "for", "return", "goto"):
                variables.append({"name": name, "type": "declared"})
        return variables

    def _extract_calls(self, code: str) -> List[str]:
        call_pattern = re.compile(r"\b(\w+)\s*\(")
        keywords = {"if", "else", "while", "for", "return", "switch", "case", "sizeof"}
        calls = set()
        for match in call_pattern.finditer(code):
            name = match.group(1)
            if name not in keywords and not name.startswith("0x"):
                calls.add(name)
        return sorted(calls)

    def _detect_loops(self, code: str) -> bool:
        loop_patterns = [r"\bwhile\b", r"\bfor\b", r"\bdo\b", r"\bgoto\s+loop", r"back-edge"]
        for pat in loop_patterns:
            if re.search(pat, code, re.IGNORECASE):
                return True
        return False

    def _detect_branches(self, code: str) -> bool:
        branch_patterns = [r"\bif\b", r"\bswitch\b", r"\belse\b", r"\bcond\b"]
        for pat in branch_patterns:
            if re.search(pat, code, re.IGNORECASE):
                return True
        return False
