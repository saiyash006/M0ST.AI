"""
Static analysis agent — AI-aware static extraction.

Responsibilities:
  - Extract disassembly (via radare2)
  - Extract CFG
  - Extract function boundaries
  - Produce structured JSON output for downstream agents
  - Populate the Program Knowledge Graph (PKG)
"""
import json
import os
from typing import Any, Dict, List, Optional

from core.capabilities import Capability
from core.config import get_config

try:
    import r2pipe
    _R2_AVAILABLE = True
except ImportError:
    _R2_AVAILABLE = False


class StaticAgent:
    """
    Disassembles a binary and builds the program graph.
    Uses radare2 via r2pipe for static analysis.
    Populates Function, BasicBlock, Instruction nodes and FLOW edges.
    """
    CAPABILITIES = {Capability.STATIC_WRITE}

    def __init__(self, graph_store, bus=None):
        self.g = graph_store
        self.bus = bus if bus is not None else type("NullBus", (), {"publish": lambda *a, **k: None})()
        self._last_structured_output: Optional[Dict[str, Any]] = None

    def run(self, binary_path: str):
        if not _R2_AVAILABLE:
            print("[StaticAgent] r2pipe is not installed. Install radare2 and r2pipe to enable static analysis.")
            print("[StaticAgent] Skipping static analysis.")
            self.bus.publish("STATIC_ANALYSIS_COMPLETE", {"function_count": 0})
            return

        if not os.path.isfile(binary_path):
            print(f"[StaticAgent] Binary not found: {binary_path}")
            self.bus.publish("STATIC_ANALYSIS_COMPLETE", {"function_count": 0})
            return

        def safe_cmdj(r2, command: str):
            try:
                return r2.cmdj(command)
            except Exception as e:
                print(f"[StaticAgent] Warning: command '{command}' failed: {e}")
                return None

        def safe_cmd(r2, command: str):
            try:
                return r2.cmd(command)
            except Exception as e:
                print(f"[StaticAgent] Warning: command '{command}' failed: {e}")
                return ""

        def parse_int(value, default=None):
            if value is None:
                return default
            try:
                return int(value)
            except (ValueError, TypeError):
                return default

        def extract_blocks(data):
            if data is None:
                return []
            if isinstance(data, list):
                if len(data) == 1 and isinstance(data[0], dict) and "blocks" in data[0]:
                    return data[0]["blocks"]
                if data and isinstance(data[0], dict) and "addr" in data[0]:
                    return data
                return data
            if isinstance(data, dict):
                if isinstance(data.get("blocks"), list):
                    return data["blocks"]
                return []
            return []

        def get_func_addr(func_dict):
            for key in ("offset", "addr", "vaddr"):
                val = parse_int(func_dict.get(key))
                if val is not None:
                    return val
            return None

        def get_func_name(func_dict, addr):
            name = func_dict.get("name") or func_dict.get("realname")
            if name:
                return name
            if addr is not None:
                return f"sub_{addr:x}"
            return None

        def _resolve_radare2home() -> Optional[str]:
            cfg = get_config()
            r2_raw = (cfg.get("tools") or {}).get("r2_path", "") or ""
            if r2_raw:
                if os.path.isdir(r2_raw):
                    return r2_raw
                if os.path.isfile(r2_raw):
                    return os.path.dirname(r2_raw)
            if os.name == "nt":
                import shutil
                if shutil.which("radare2") or shutil.which("r2"):
                    return None
                _candidate_dirs = [
                    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "radare2", "bin"),
                    os.path.join(os.environ.get("LOCALAPPDATA", ""), "radare2", "bin"),
                    r"C:\radare2\bin",
                    r"C:\Program Files\radare2\bin",
                    r"C:\Program Files (x86)\radare2\bin",
                    os.path.join(os.environ.get("USERPROFILE", ""), "scoop", "apps", "radare2", "current", "bin"),
                    os.path.join(os.environ.get("USERPROFILE", ""), "radare2", "bin"),
                ]
                for d in _candidate_dirs:
                    if os.path.isfile(os.path.join(d, "radare2.exe")):
                        return d
            return None

        r2 = None
        function_count = 0
        block_count = 0
        insn_count = 0
        edge_count = 0

        try:
            radare2home = _resolve_radare2home()
            try:
                r2 = r2pipe.open(binary_path, radare2home=radare2home)
            except FileNotFoundError:
                print("[StaticAgent] Error: radare2 not found.")
                if os.name == "nt":
                    print("[StaticAgent] Install radare2 from https://github.com/radareorg/radare2/releases")
                    print("[StaticAgent] Then either add it to PATH, or set 'tools.r2_path' in config.yml")
                else:
                    print("[StaticAgent] Install radare2 and ensure it is on your PATH,")
                    print("[StaticAgent] or set 'tools.r2_path' in config.yml to the radare2 directory.")
                self.bus.publish("STATIC_ANALYSIS_COMPLETE", {"function_count": 0})
                return

            safe_cmd(r2, "e bin.relocs.apply=true")
            safe_cmd(r2, "e bin.cache=true")
            safe_cmd(r2, "aaa")

            functions = safe_cmdj(r2, "aflj")
            if not isinstance(functions, list):
                functions = safe_cmdj(r2, "afj")
            if not isinstance(functions, list):
                print("[StaticAgent] Warning: no function list returned from radare2.")
                functions = []

            print(f"[StaticAgent] radare2 reported {len(functions)} function(s).")

            for func in functions:
                if not isinstance(func, dict):
                    continue

                func_addr = get_func_addr(func)
                func_name = get_func_name(func, func_addr)

                if func_addr is None or func_name is None:
                    continue

                self.g.create_function(func_name, func_addr)
                function_count += 1

                agfbj = safe_cmdj(r2, f"afbj @{func_addr}")
                if agfbj is None:
                    agfbj = safe_cmdj(r2, f"agfbj {func_addr}")
                blocks = extract_blocks(agfbj)

                block_addrs = []
                for block in blocks:
                    if not isinstance(block, dict):
                        continue
                    bb_addr = parse_int(block.get("addr"))
                    if bb_addr is None:
                        continue
                    block_addrs.append(bb_addr)
                    self.g.create_basic_block(func_addr, bb_addr)
                    block_count += 1

                block_set = set(block_addrs)
                for block in blocks:
                    if not isinstance(block, dict):
                        continue
                    src_addr = parse_int(block.get("addr"))
                    if src_addr is None:
                        continue

                    dsts = []
                    if isinstance(block.get("edges"), list):
                        for edge in block["edges"]:
                            if isinstance(edge, dict):
                                dsts.append(parse_int(edge.get("to")))
                            else:
                                dsts.append(parse_int(edge))
                    else:
                        dsts.append(parse_int(block.get("jump")))
                        dsts.append(parse_int(block.get("fail")))

                    for dst in dsts:
                        if dst is not None and dst in block_set:
                            self.g.add_flow_edge(src_addr, dst)
                            edge_count += 1

                for block in blocks:
                    if not isinstance(block, dict):
                        continue
                    bb_addr = parse_int(block.get("addr"))
                    bb_size = parse_int(block.get("size"), 0)
                    if bb_addr is None or bb_size is None or bb_size <= 0:
                        continue

                    insns = safe_cmdj(r2, f"pDj {bb_size} @ {bb_addr}")
                    if not isinstance(insns, list):
                        insns = safe_cmdj(r2, f"pdj 64 @ {bb_addr}")
                    if not isinstance(insns, list):
                        continue

                    for insn in insns:
                        if not isinstance(insn, dict):
                            continue
                        insn_addr = parse_int(insn.get("offset"))
                        if insn_addr is None:
                            insn_addr = parse_int(insn.get("addr"))
                        if insn_addr is None:
                            continue
                        if insn_addr < bb_addr or insn_addr >= bb_addr + bb_size:
                            continue

                        mnemonic = insn.get("mnemonic")
                        if not mnemonic:
                            opcode = insn.get("opcode") or insn.get("disasm") or ""
                            if isinstance(opcode, str) and opcode.strip():
                                mnemonic = opcode.strip().split()[0]
                        if not mnemonic:
                            continue

                        operands = []
                        op_str = insn.get("op_str") or insn.get("esil")
                        if isinstance(op_str, str) and op_str.strip():
                            operands = [o.strip() for o in op_str.split(",") if o.strip()]

                        self.g.create_instruction(bb_addr, insn_addr, mnemonic, operands)
                        insn_count += 1

        except Exception as e:
            print(f"[StaticAgent] Error during analysis: {e}")
        finally:
            if r2 is not None:
                try:
                    r2.quit()
                except Exception:
                    pass

        print(f"[StaticAgent] Created {function_count} functions, "
              f"{block_count} blocks, {edge_count} edges, {insn_count} instructions.")
        self.bus.publish("STATIC_ANALYSIS_COMPLETE", {"function_count": function_count})

        self._last_structured_output = self._build_structured_output(binary_path)

    def get_structured_output(self) -> Optional[Dict[str, Any]]:
        return self._last_structured_output

    def _build_structured_output(self, binary_path: str) -> Dict[str, Any]:
        output = {
            "binary_path": binary_path,
            "functions": [],
            "strings": self._extract_strings_from_store(),
            "imports": self._extract_imports_from_store(),
            "exports": self._extract_exports_from_store(),
        }

        for func in self.g.fetch_functions():
            addr = func.get("addr")
            if addr is None:
                continue
            blocks = self.g.fetch_basic_blocks(addr)
            edges = self.g.fetch_flow_edges(addr)

            func_data = {
                "name": func.get("name", f"sub_{addr:x}"),
                "addr": addr,
                "addr_hex": f"0x{addr:x}",
                "block_count": len(blocks),
                "edge_count": len(edges),
                "blocks": [],
                "edges": [{"src": s, "dst": d} for s, d in edges],
            }

            for bb in blocks:
                insns = self.g.fetch_block_instructions(bb)
                func_data["blocks"].append({
                    "addr": bb,
                    "instructions": [
                        {
                            "addr": insn.get("addr", 0),
                            "mnemonic": insn.get("mnemonic", ""),
                            "operands": insn.get("operands", []),
                        }
                        for insn in insns
                    ],
                })

            output["functions"].append(func_data)

        return output

    def _extract_strings_from_store(self) -> List[str]:
        if hasattr(self.g, "fetch_strings"):
            return self.g.fetch_strings()
        return []

    def _extract_imports_from_store(self) -> List[str]:
        if hasattr(self.g, "fetch_imports"):
            return self.g.fetch_imports()
        return []

    def _extract_exports_from_store(self) -> List[str]:
        if hasattr(self.g, "fetch_exports"):
            return self.g.fetch_exports()
        return []
