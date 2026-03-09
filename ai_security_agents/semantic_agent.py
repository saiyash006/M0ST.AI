import re
from typing import Dict, List, Optional, Set, Tuple

from core.capabilities import Capability

# Known libc / common functions and their behavioral descriptions
_BEHAVIOR_MAP = {
    "printf": "Outputs formatted text to stdout",
    "puts": "Outputs a string to stdout",
    "fprintf": "Outputs formatted text to a file stream",
    "sprintf": "Writes formatted text to a buffer (unsafe)",
    "snprintf": "Writes formatted text to a sized buffer",
    "scanf": "Reads formatted input from stdin",
    "fscanf": "Reads formatted input from a file stream",
    "sscanf": "Reads formatted input from a string",
    "gets": "Reads a line from stdin (unsafe, no bounds check)",
    "fgets": "Reads a line from a stream with a size limit",
    "read": "Reads bytes from a file descriptor",
    "write": "Writes bytes to a file descriptor",
    "open": "Opens a file descriptor",
    "close": "Closes a file descriptor",
    "malloc": "Allocates heap memory",
    "calloc": "Allocates and zeroes heap memory",
    "realloc": "Resizes a heap allocation",
    "free": "Frees heap memory",
    "memcpy": "Copies memory between buffers",
    "memmove": "Copies memory (overlap-safe)",
    "memset": "Fills memory with a byte value",
    "strlen": "Computes string length",
    "strcmp": "Compares two strings",
    "strncmp": "Compares two strings up to N bytes",
    "strcpy": "Copies a string (unsafe, no bounds check)",
    "strncpy": "Copies a string up to N bytes",
    "strcat": "Concatenates strings (unsafe)",
    "exit": "Terminates the process",
    "_exit": "Terminates the process immediately",
    "abort": "Aborts the process with a signal",
    "atoi": "Converts a string to an integer",
    "atol": "Converts a string to a long integer",
    "strtol": "Converts a string to a long with error checking",
    "socket": "Creates a network socket",
    "connect": "Connects a socket to an address",
    "bind": "Binds a socket to an address",
    "listen": "Marks a socket as listening",
    "accept": "Accepts a connection on a socket",
    "send": "Sends data on a socket",
    "recv": "Receives data from a socket",
    "fork": "Creates a child process",
    "execve": "Replaces the current process image",
    "system": "Executes a shell command",
    "mmap": "Maps memory pages",
    "munmap": "Unmaps memory pages",
}


class SemanticAgent:
    """
    Generates human-level understanding using classical heuristics.
    Responsibilities:
    - Read normalized CFG, IR, and dataflow.
    - Produce multi-level explanations of function logic.
    - Detect high-level intent of code.
    - Identify potential vulnerabilities.
    - Output summaries that humans can understand.
    """
    CAPABILITIES = {Capability.SEMANTIC_REASON, Capability.STATIC_READ}

    def __init__(self, graph_store, bus=None):
        self.g = graph_store
        self.bus = bus

    def explain_simple(self, func_addr: int) -> Dict:
        func_name = self._lookup_function_name(func_addr)
        blocks = self.g.fetch_basic_blocks(func_addr)
        edges = self.g.fetch_flow_edges(func_addr)
        block_insns = {bb: self.g.fetch_block_instructions(bb) for bb in blocks}
        calls = self._collect_calls(block_insns)
        loops = self._detect_back_edges(blocks, edges)
        hints = self._infer_behavior_hints(calls, block_insns, blocks)
        summary = (
            f"{func_name} performs {len(calls)} call(s) and has "
            f"{len(loops)} loop(s) across {len(blocks)} blocks."
        )
        steps = []
        if hints:
            for h in hints:
                steps.append(h)
        return {
            "summary": summary,
            "steps": steps,
            "variables": [],
            "vulnerabilities": [],
        }

    def explain_medium(self, func_addr: int) -> Dict:
        return self.explain_function(func_addr)

    def explain_deep(self, func_addr: int) -> Dict:
        func_name = self._lookup_function_name(func_addr)
        blocks = self.g.fetch_basic_blocks(func_addr)
        edges = self.g.fetch_flow_edges(func_addr)

        block_insns = {
            bb: self.g.fetch_block_instructions(bb) for bb in blocks
        }

        calls = self._collect_calls(block_insns)
        loops = self._detect_back_edges(blocks, edges)
        variables = self._extract_variables(block_insns)
        vulnerabilities = self._detect_vulnerabilities(block_insns, calls)
        hints = self._infer_behavior_hints(calls, block_insns, blocks)

        steps = []
        if blocks:
            steps.append(
                f"Builds CFG with {len(blocks)} basic blocks and {len(edges)} edges."
            )
        if loops:
            steps.append(
                f"Contains {len(loops)} loop(s) based on back-edges to earlier blocks."
            )
        if calls:
            steps.append(f"Calls {len(calls)} target(s): {', '.join(calls)}.")
        if self._has_branching(block_insns):
            steps.append("Performs conditional branching based on comparisons or tests.")
        if self._has_memory_ops(block_insns):
            steps.append("Moves or manipulates memory through load/store-like instructions.")
        if variables:
            steps.append(f"Observes {len(variables)} variables from registers/stack/immediates.")
        if hints:
            for h in hints:
                steps.append(f"Behavior: {h}")
        if vulnerabilities:
            steps.append(f"Flags {len(vulnerabilities)} potential vulnerability indicator(s).")

        summary = self._build_summary(
            func_name=func_name,
            func_addr=func_addr,
            blocks=len(blocks),
            edges=len(edges),
            loops=len(loops),
            calls=calls,
        )

        return {
            "summary": summary,
            "steps": steps,
            "variables": variables,
            "vulnerabilities": vulnerabilities,
        }

    def explain(self, func_addr: int, level: str = "medium") -> Dict:
        if level == "simple":
            return self.explain_simple(func_addr)
        if level == "deep":
            return self.explain_deep(func_addr)
        return self.explain_medium(func_addr)

    def explain_function(self, func_addr: int) -> Dict:
        func_name = self._lookup_function_name(func_addr)
        blocks = self.g.fetch_basic_blocks(func_addr)
        edges = self.g.fetch_flow_edges(func_addr)

        block_insns = {
            bb: self.g.fetch_block_instructions(bb) for bb in blocks
        }

        calls = self._collect_calls(block_insns)
        loops = self._detect_back_edges(blocks, edges)
        variables = self._extract_variables(block_insns)
        vulnerabilities = self._detect_vulnerabilities(block_insns, calls)
        hints = self._infer_behavior_hints(calls, block_insns, blocks)

        steps = []
        if blocks:
            steps.append(
                f"Builds CFG with {len(blocks)} basic blocks and {len(edges)} edges."
            )
        if loops:
            steps.append(
                f"Contains {len(loops)} loop(s) based on back-edges to earlier blocks."
            )
        if calls:
            steps.append(f"Calls {len(calls)} external/internal target(s): {', '.join(calls)}.")
        if self._has_branching(block_insns):
            steps.append("Performs conditional branching based on comparisons or tests.")
        if self._has_memory_ops(block_insns):
            steps.append("Moves or manipulates memory through load/store-like instructions.")
        if variables:
            steps.append(f"Observes {len(variables)} variables from registers/stack/immediates.")
        if hints:
            for h in hints:
                steps.append(f"Behavior: {h}")

        summary = self._build_summary(
            func_name=func_name,
            func_addr=func_addr,
            blocks=len(blocks),
            edges=len(edges),
            loops=len(loops),
            calls=calls,
        )

        result = {
            "summary": summary,
            "steps": steps,
            "variables": variables,
            "vulnerabilities": vulnerabilities,
        }

        if self.bus is not None:
            self.bus.publish(
                "SEMANTIC_EXPLANATION_READY",
                {"func_addr": func_addr, "summary": summary},
            )

        return result

    # ---------------------------
    # Data extraction
    # ---------------------------

    def _lookup_function_name(self, func_addr: int) -> str:
        for func in self.g.fetch_functions():
            if func.get("addr") == func_addr:
                return func.get("name") or f"sub_{func_addr:x}"
        return f"sub_{func_addr:x}"

    def _collect_calls(self, block_insns: Dict[int, List[Dict]]) -> List[str]:
        targets: Set[str] = set()
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem in {"call", "bl", "blr"}:
                    ops = insn.get("operands") or []
                    if ops:
                        resolved = self._resolve_call_name(ops[0])
                        targets.add(resolved)
        return sorted(targets)

    def _detect_back_edges(
        self, blocks: List[int], edges: List[Tuple[int, int]]
    ) -> List[Tuple[int, int]]:
        block_set = set(blocks)
        back_edges = []
        for src, dst in edges:
            if src in block_set and dst in block_set and dst <= src:
                back_edges.append((src, dst))
        return back_edges

    def _extract_variables(self, block_insns: Dict[int, List[Dict]]) -> List[Dict]:
        regs = set()
        stack_vars = set()
        immediates = set()

        reg_pattern = re.compile(r"\b(r[abcd]x|r[bs]p|r[sd]i|r\d+|e[abcd]x|e[bs]p|e[sd]i)\b", re.IGNORECASE)
        stack_pattern = re.compile(r"\[(rbp|rsp|ebp|esp)[+-]0x[0-9a-fA-F]+\]")
        imm_pattern = re.compile(r"\b0x[0-9a-fA-F]+\b|\b\d+\b")

        for insns in block_insns.values():
            for insn in insns:
                for op in insn.get("operands") or []:
                    for r in reg_pattern.findall(op):
                        regs.add(r.lower())
                    for s in stack_pattern.findall(op):
                        stack_vars.add(op)
                    for imm in imm_pattern.findall(op):
                        immediates.add(imm)

        variables = []
        for r in sorted(regs):
            variables.append({"name": r, "type": "register"})
        for s in sorted(stack_vars):
            variables.append({"name": s, "type": "stack_slot"})
        for imm in sorted(immediates):
            variables.append({"name": imm, "type": "immediate"})
        return variables

    def _detect_vulnerabilities(
        self, block_insns: Dict[int, List[Dict]], calls: List[str]
    ) -> List[Dict]:
        vulns = []
        unsafe = {"strcpy", "strcat", "gets", "sprintf", "vsprintf"}
        for target in calls:
            name = target.lower()
            if any(u in name for u in unsafe):
                vulns.append(
                    {
                        "type": "unsafe_call",
                        "detail": f"Call to {target} may be unsafe without bounds checks.",
                    }
                )

        if self._has_stack_alloc(block_insns) and not self._has_stack_checks(block_insns):
            vulns.append(
                {
                    "type": "stack_allocation",
                    "detail": "Stack allocation detected without obvious bounds checks.",
                }
            )

        return vulns

    # ---------------------------
    # Heuristic helpers
    # ---------------------------

    def _has_branching(self, block_insns: Dict[int, List[Dict]]) -> bool:
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem.startswith("j") and mnem != "jmp":
                    return True
        return False

    def _has_memory_ops(self, block_insns: Dict[int, List[Dict]]) -> bool:
        mem_mnems = {"mov", "movs", "stos", "lods"}
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem in mem_mnems:
                    return True
        return False

    def _has_stack_alloc(self, block_insns: Dict[int, List[Dict]]) -> bool:
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                ops = insn.get("operands") or []
                if mnem == "sub" and len(ops) >= 2 and ops[0].lower() in {"rsp", "esp"}:
                    return True
        return False

    def _has_stack_checks(self, block_insns: Dict[int, List[Dict]]) -> bool:
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem in {"cmp", "test"}:
                    return True
        return False

    def _resolve_call_name(self, target: str) -> str:
        if not isinstance(target, str):
            return str(target)

        try:
            if target.startswith("0x") or target.startswith("-0x"):
                addr = int(target, 16)
            elif target.isdigit():
                addr = int(target)
            else:
                addr = None
        except (ValueError, TypeError):
            addr = None

        if addr is not None:
            for func in self.g.fetch_functions():
                if func.get("addr") == addr:
                    name = func.get("name", target)
                    return self._clean_symbol_name(name)
            return f"sub_0x{addr:x}"

        return self._clean_symbol_name(target)

    def _clean_symbol_name(self, name: str) -> str:
        if name.startswith("sym.imp."):
            return name[8:]
        if name.startswith("sym."):
            return name[4:]
        if name.startswith("fcn."):
            try:
                addr = int(name[4:], 16)
                return f"sub_0x{addr:x}"
            except ValueError:
                pass
        return name

    def _infer_behavior_hints(
        self,
        calls: List[str],
        block_insns: Dict[int, List[Dict]],
        blocks: List[int],
    ) -> List[str]:
        hints: List[str] = []

        for call_target in calls:
            base = call_target
            for prefix in ("sym.imp.", "sym.", "plt."):
                if base.startswith(prefix):
                    base = base[len(prefix):]
            desc = _BEHAVIOR_MAP.get(base)
            if desc:
                hints.append(f"{desc} (via {base})")

        if len(blocks) == 1:
            total_insns = sum(len(insns) for insns in block_insns.values())
            if not calls:
                hints.append("Leaf function (single block, no calls)")
            elif total_insns <= 5:
                hints.append("Thin wrapper function")

        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem in {"syscall", "int", "svc"}:
                    hints.append("Makes direct system calls")
                    break
            else:
                continue
            break

        return hints

    def _build_summary(
        self,
        func_name: str,
        func_addr: int,
        blocks: int,
        edges: int,
        loops: int,
        calls: List[str],
    ) -> str:
        call_part = "no obvious calls" if not calls else f"{len(calls)} call(s)"
        loop_part = "no detected loops" if loops == 0 else f"{loops} loop(s)"
        call_names = ""
        if calls:
            call_names = f" Targets: {', '.join(calls)}."
        return (
            f"{func_name} @ 0x{func_addr:x} has {blocks} blocks / {edges} edges, "
            f"{loop_part}, and {call_part}.{call_names}"
        )
