"""
Type Inference module — Infers data types from binary analysis.

Combines heuristic analysis of instruction patterns with
AI-assisted type propagation to recover variable types,
struct layouts, and function signatures.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple


class TypeInferenceEngine:
    """
    Recovers type information from disassembly and pseudocode.
    """

    # Common register widths on x86-64
    _REG_WIDTHS = {
        "rax": 8, "rbx": 8, "rcx": 8, "rdx": 8,
        "rsi": 8, "rdi": 8, "rsp": 8, "rbp": 8,
        "r8": 8, "r9": 8, "r10": 8, "r11": 8,
        "r12": 8, "r13": 8, "r14": 8, "r15": 8,
        "eax": 4, "ebx": 4, "ecx": 4, "edx": 4,
        "esi": 4, "edi": 4, "esp": 4, "ebp": 4,
        "ax": 2, "bx": 2, "cx": 2, "dx": 2,
        "al": 1, "bl": 1, "cl": 1, "dl": 1,
        "ah": 1, "bh": 1, "ch": 1, "dh": 1,
    }

    # System V AMD64 ABI argument registers
    _ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

    def infer_function_signature(
        self,
        graph_store,
        func_addr: int,
    ) -> Dict[str, Any]:
        """
        Infer function signature from argument register usage
        and return value patterns.
        """
        blocks = graph_store.fetch_basic_blocks(func_addr)
        if not blocks:
            return {"args": [], "return_type": "void"}

        entry = func_addr if func_addr in blocks else min(blocks)
        entry_insns = graph_store.fetch_block_instructions(entry)

        # Detect argument registers read before written
        args = self._detect_arguments(entry_insns)

        # Detect return type from last block
        return_type = self._detect_return_type(graph_store, blocks)

        return {
            "args": args,
            "return_type": return_type,
        }

    def infer_local_variables(
        self,
        graph_store,
        func_addr: int,
    ) -> List[Dict[str, Any]]:
        """
        Infer local variable types from stack access patterns.
        """
        blocks = graph_store.fetch_basic_blocks(func_addr)
        stack_accesses: Dict[str, Dict[str, Any]] = {}

        stack_pattern = re.compile(
            r"\[(rbp|ebp)\s*-\s*0x([0-9a-fA-F]+)\]"
        )

        for bb in blocks:
            insns = graph_store.fetch_block_instructions(bb)
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                ops = insn.get("operands") or []
                for i, op in enumerate(ops):
                    match = stack_pattern.search(op)
                    if match:
                        offset = int(match.group(2), 16)
                        key = f"local_{offset:x}"
                        if key not in stack_accesses:
                            stack_accesses[key] = {
                                "offset": offset,
                                "reads": 0,
                                "writes": 0,
                                "width": None,
                            }
                        if i == 0 and mnem in ("mov", "lea", "movzx", "movsx"):
                            stack_accesses[key]["writes"] += 1
                        else:
                            stack_accesses[key]["reads"] += 1

                        # Infer width from instruction
                        width = self._infer_width_from_mnem(mnem, ops)
                        if width:
                            stack_accesses[key]["width"] = width

        locals_list = []
        for name, info in sorted(stack_accesses.items(), key=lambda x: x[1]["offset"]):
            type_str = self._width_to_type(info.get("width"))
            locals_list.append({
                "name": name,
                "offset": info["offset"],
                "type": type_str,
                "reads": info["reads"],
                "writes": info["writes"],
            })

        return locals_list

    def _detect_arguments(self, entry_insns: List[Dict]) -> List[Dict[str, str]]:
        """Detect function arguments from register usage in entry block."""
        written_regs: Set[str] = set()
        args = []

        for insn in entry_insns:
            mnem = (insn.get("mnemonic") or "").lower()
            ops = insn.get("operands") or []

            # Check if argument registers are read before written
            for i, op in enumerate(ops):
                op_lower = op.lower()
                for arg_idx, arg_reg in enumerate(self._ARG_REGS):
                    if arg_reg in op_lower and arg_reg not in written_regs:
                        if i > 0 or mnem not in ("mov", "lea", "xor"):
                            args.append({
                                "index": arg_idx,
                                "register": arg_reg,
                                "type": "unknown",
                            })
                            written_regs.add(arg_reg)

            # Track writes
            if ops and mnem in ("mov", "lea", "xor", "pop"):
                dst = ops[0].lower()
                for reg in self._ARG_REGS:
                    if reg in dst:
                        written_regs.add(reg)

        # Deduplicate and sort by index
        seen = set()
        unique_args = []
        for arg in sorted(args, key=lambda a: a["index"]):
            if arg["index"] not in seen:
                seen.add(arg["index"])
                unique_args.append(arg)

        return unique_args

    def _detect_return_type(self, graph_store, blocks: List[int]) -> str:
        """Detect return type from the return block's use of rax/eax."""
        for bb in blocks:
            insns = graph_store.fetch_block_instructions(bb)
            if not insns:
                continue
            last = insns[-1]
            mnem = (last.get("mnemonic") or "").lower()
            if mnem in ("ret", "retq", "retn"):
                # Check if rax/eax was written in this block
                for insn in reversed(insns[:-1]):
                    ins_mnem = (insn.get("mnemonic") or "").lower()
                    ops = insn.get("operands") or []
                    if ops and ins_mnem in ("mov", "lea", "xor"):
                        dst = ops[0].lower()
                        if "rax" in dst:
                            return "int64"
                        if "eax" in dst:
                            return "int32"
                        if "al" in dst:
                            return "bool"
                # xor eax, eax pattern = returns 0
                for insn in insns:
                    ins_mnem = (insn.get("mnemonic") or "").lower()
                    ops = insn.get("operands") or []
                    if ins_mnem == "xor" and len(ops) >= 2:
                        if ops[0].lower() == ops[1].lower() and "eax" in ops[0].lower():
                            return "int32"
                return "int"
        return "void"

    def _infer_width_from_mnem(self, mnem: str, ops: List[str]) -> Optional[int]:
        """Infer access width from instruction and operands."""
        if "byte" in " ".join(ops).lower():
            return 1
        if "word" in " ".join(ops).lower() and "dword" not in " ".join(ops).lower():
            return 2
        if "dword" in " ".join(ops).lower():
            return 4
        if "qword" in " ".join(ops).lower():
            return 8

        if mnem in ("movzx", "movsx"):
            return 1  # Usually byte extension

        # Infer from register in destination
        if ops:
            dst = ops[0].lower()
            return self._REG_WIDTHS.get(dst)

        return None

    def _width_to_type(self, width: Optional[int]) -> str:
        """Convert byte width to a C-like type string."""
        if width == 1:
            return "uint8_t"
        if width == 2:
            return "uint16_t"
        if width == 4:
            return "uint32_t"
        if width == 8:
            return "uint64_t"
        return "unknown"
