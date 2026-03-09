import re
from typing import Dict, List, Optional, Tuple

from ai_security_agents.z3_agent import Z3Agent


_COND_JUMPS = {
    "je",
    "jz",
    "jne",
    "jnz",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jc",
    "jnc",
}


def prune_infeasible_edges(graph_store):
    """
    Remove FLOW edges that are impossible due to constant conditional branches.
    This pass only prunes when a branch condition is provably constant.
    """
    solver = Z3Agent()
    functions = graph_store.fetch_functions()
    for func in functions:
        func_addr = func.get("addr")
        if func_addr is None:
            continue
        blocks = graph_store.fetch_basic_blocks(func_addr)
        for bb in blocks:
            insns = graph_store.fetch_block_instructions(bb)
            if not insns:
                continue
            jump = _get_last_conditional_jump(insns)
            if jump is None:
                continue

            jump_mnem, jump_target = jump
            if jump_target is None:
                continue

            edges = graph_store.fetch_flow_edges_from(bb)
            succs = [dst for _, dst in edges]
            if len(succs) != 2:
                continue

            taken = jump_target
            fallthrough = succs[0] if succs[0] != taken else succs[1]

            expr = _build_branch_expr(insns, jump_mnem, solver)
            if expr is None:
                continue

            if not solver.check_branch_feasible(expr):
                graph_store.remove_flow_edge(bb, taken)
                continue

            neg_expr = f"not ({expr})"
            if not solver.check_branch_feasible(neg_expr):
                graph_store.remove_flow_edge(bb, fallthrough)


def _get_last_conditional_jump(
    insns: List[Dict],
) -> Optional[Tuple[str, Optional[int]]]:
    last = insns[-1]
    mnem = (last.get("mnemonic") or "").lower()
    if not mnem:
        return None
    if mnem == "jmp" or not mnem.startswith("j"):
        return None
    if mnem not in _COND_JUMPS:
        return None

    ops = last.get("operands") or []
    target = _parse_int_operand(ops[0]) if ops else None
    return mnem, target


def _build_branch_expr(
    insns: List[Dict],
    jump_mnem: str,
    solver: Z3Agent,
) -> Optional[str]:
    cmp_insn = _find_last_cmp_like(insns)
    if cmp_insn is None:
        return None

    mnem = (cmp_insn.get("mnemonic") or "").lower()
    ops = cmp_insn.get("operands") or []
    if len(ops) < 2:
        return None

    left = _parse_int_operand(ops[0])
    right = _parse_int_operand(ops[1])
    if left is None or right is None:
        return None

    if mnem == "test":
        value = left & right
        return _expr_from_jump(jump_mnem, value)

    base = f"({left} - {right})"
    return _expr_from_jump(jump_mnem, base)


def _expr_from_jump(jump_mnem: str, base) -> Optional[str]:
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
    if jump_mnem in {"ja", "jae", "jb", "jbe", "jc", "jnc"}:
        return None
    return None


def _find_last_cmp_like(insns: List[Dict]) -> Optional[Dict]:
    for insn in reversed(insns[:-1]):
        mnem = (insn.get("mnemonic") or "").lower()
        if mnem in {"cmp", "test"}:
            return insn
    return None


def _parse_int_operand(op: str) -> Optional[int]:
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
