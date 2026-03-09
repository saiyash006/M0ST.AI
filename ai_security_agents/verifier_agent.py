import re
from typing import Dict, List, Optional, Set, Tuple

from core.capabilities import Capability
from ai_security_agents.z3_agent import Z3Agent


class VerifierAgent:
    """
    Validates claims made by AI or heuristic agents.
    Responsibilities:
    - Cross-check semantic explanations with static/dynamic facts.
    - Use Z3Agent to verify logic conditions.
    - Detect contradictions and request re-analysis.
    - Publish VERIFY_RESULT.
    """
    CAPABILITIES = {Capability.VERIFY, Capability.STATIC_READ}

    def __init__(self, graph_store, bus=None):
        self.g = graph_store
        self.bus = bus
        self.z3 = Z3Agent()

    def verify_basicblock_edges(self):
        static_edges = set(self.g.fetch_all_flow_edges())
        runtime_edges = set(self.g.fetch_runtime_flow_edges())
        executed_blocks = set(self.g.fetch_executed_blocks())

        static_not_dynamic = sorted(e for e in static_edges if e not in runtime_edges)
        dynamic_not_static = sorted(e for e in runtime_edges if e not in static_edges)
        unreachable_blocks = sorted(
            b for b in self.g.fetch_all_basic_blocks() if b not in executed_blocks
        ) if executed_blocks else []

        suspect = 0
        for edge in static_not_dynamic:
            self.g.mark_flow_edge_suspect(edge[0], edge[1])
            suspect += 1

        branch_issues = self._verify_branch_conditions()
        unsafe_patterns = self._detect_unsafe_patterns()

        results = {
            "suspect_edges": suspect,
            "static_edges": len(static_edges),
            "runtime_edges": len(runtime_edges),
            "static_not_dynamic": static_not_dynamic,
            "dynamic_not_static": dynamic_not_static,
            "unreachable_blocks": unreachable_blocks,
            "branch_issues": branch_issues,
            "unsafe_patterns": unsafe_patterns,
        }
        self.g.set_verification_results(results)

        if self.bus is not None:
            self.bus.publish("VERIFY_RESULT", results)

    # ---------------------------
    # Advanced checks
    # ---------------------------

    def _verify_branch_conditions(self) -> List[Dict]:
        issues: List[Dict] = []
        for func in self.g.fetch_functions():
            func_addr = func.get("addr")
            if func_addr is None:
                continue
            blocks = self.g.fetch_basic_blocks(func_addr)
            for bb in blocks:
                insns = self.g.fetch_block_instructions(bb)
                if not insns:
                    continue
                last = insns[-1]
                mnem = (last.get("mnemonic") or "").lower()
                if not mnem.startswith("j") or mnem in {"jmp", "jmpq"}:
                    continue
                edges = self.g.fetch_flow_edges_from(bb)
                if len(edges) != 2:
                    continue
                expr = self._build_branch_expr(insns, mnem)
                if expr is None:
                    continue
                taken = self._parse_int_operand((last.get("operands") or [None])[0])
                succs = [dst for _, dst in edges]
                if taken is None:
                    continue
                fallthrough = succs[0] if succs[0] != taken else succs[1]

                if not self.z3.check_branch_feasible(expr):
                    issues.append(
                        {
                            "bb": bb,
                            "edge": (bb, taken),
                            "reason": "taken_infeasible",
                            "expr": expr,
                        }
                    )
                neg_expr = f"not ({expr})"
                if not self.z3.check_branch_feasible(neg_expr):
                    issues.append(
                        {
                            "bb": bb,
                            "edge": (bb, fallthrough),
                            "reason": "fallthrough_infeasible",
                            "expr": neg_expr,
                        }
                    )
        return issues

    def _detect_unsafe_patterns(self) -> List[Dict]:
        unsafe = []
        unsafe_funcs = {"strcpy", "strcat", "gets", "sprintf", "vsprintf"}
        for func in self.g.fetch_functions():
            func_addr = func.get("addr")
            if func_addr is None:
                continue
            blocks = self.g.fetch_basic_blocks(func_addr)
            block_insns = [self.g.fetch_block_instructions(bb) for bb in blocks]

            if self._has_stack_alloc(block_insns) and not self._has_stack_checks(block_insns):
                unsafe.append(
                    {
                        "func": func_addr,
                        "type": "stack_allocation",
                        "detail": "Stack allocation detected without obvious bounds checks.",
                    }
                )

            for insns in block_insns:
                for insn in insns:
                    mnem = (insn.get("mnemonic") or "").lower()
                    if mnem in {"call", "bl", "blr"}:
                        ops = insn.get("operands") or []
                        if not ops:
                            continue
                        target = ops[0].lower()
                        if any(u in target for u in unsafe_funcs):
                            unsafe.append(
                                {
                                    "func": func_addr,
                                    "type": "unsafe_call",
                                    "detail": f"Call to {ops[0]} may be unsafe without bounds checks.",
                                }
                            )
        return unsafe

    # ---------------------------
    # Branch expression helpers
    # ---------------------------

    def _build_branch_expr(self, insns: List[Dict], jump_mnem: str) -> Optional[str]:
        cmp_insn = self._find_last_cmp_like(insns)
        if cmp_insn is None:
            return None
        mnem = (cmp_insn.get("mnemonic") or "").lower()
        ops = cmp_insn.get("operands") or []
        if len(ops) < 2:
            return None
        left = self._parse_int_operand(ops[0])
        right = self._parse_int_operand(ops[1])
        if left is None or right is None:
            return None
        if mnem == "test":
            value = left & right
            return self._expr_from_jump(jump_mnem, value)
        base = f"({left} - {right})"
        return self._expr_from_jump(jump_mnem, base)

    def _expr_from_jump(self, jump_mnem: str, base) -> Optional[str]:
        if jump_mnem in {"je", "jz"}:
            return f"{base} == 0"
        if jump_mnem in {"jne", "jnz"}:
            return f"{base} != 0"
        if jump_mnem == "jg":
            return f"{base} > 0"
        if jump_mnem == "jge":
            return f"{base} >= 0"
        if jump_mnem == "jl":
            return f"{base} < 0"
        if jump_mnem == "jle":
            return f"{base} <= 0"
        return None

    def _find_last_cmp_like(self, insns: List[Dict]) -> Optional[Dict]:
        for insn in reversed(insns[:-1]):
            mnem = (insn.get("mnemonic") or "").lower()
            if mnem in {"cmp", "test"}:
                return insn
        return None

    def _parse_int_operand(self, op: Optional[str]) -> Optional[int]:
        if not isinstance(op, str):
            return None
        match = re.search(r"-?0x[0-9a-fA-F]+|-?\d+", op)
        if not match:
            return None
        text = match.group(0)
        try:
            if text.startswith("0x") or text.startswith("-0x"):
                return int(text, 16)
            return int(text, 10)
        except Exception:
            return None

    # ---------------------------
    # Unsafe heuristics helpers
    # ---------------------------

    def _has_stack_alloc(self, block_insns: List[List[Dict]]) -> bool:
        for insns in block_insns:
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                ops = insn.get("operands") or []
                if mnem == "sub" and len(ops) >= 2 and ops[0].lower() in {"rsp", "esp"}:
                    return True
        return False

    def _has_stack_checks(self, block_insns: List[List[Dict]]) -> bool:
        for insns in block_insns:
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem in {"cmp", "test"}:
                    return True
        return False
