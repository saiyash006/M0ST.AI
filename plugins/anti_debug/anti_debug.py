"""
Anti-debug detection plugin.
Looks for common anti-debugging patterns in function instructions.
"""

ANTI_DEBUG_CALLS = {
    "ptrace", "isdebuggerpresent", "ntqueryinformationprocess",
    "checkremotedebuggerpresent", "outputdebugstring",
}

ANTI_DEBUG_INSNS = {
    "int3", "int1", "icebp", "rdtsc",
}


def analyze(graph_store, func_addr: int) -> dict:
    """
    Detect anti-debugging techniques in a function.
    Returns a dict of findings.
    """
    blocks = graph_store.fetch_basic_blocks(func_addr)
    findings = []

    for bb in blocks:
        insns = graph_store.fetch_block_instructions(bb)
        for insn in insns:
            mnem = (insn.get("mnemonic") or "").lower()
            ops = insn.get("operands") or []

            # Check for anti-debug instruction patterns
            if mnem in ANTI_DEBUG_INSNS:
                findings.append({
                    "type": "anti_debug_instruction",
                    "addr": insn.get("addr"),
                    "detail": f"Anti-debug instruction '{mnem}' detected.",
                })

            # Check for anti-debug API calls
            if mnem in {"call", "bl", "blr"} and ops:
                target = ops[0].lower()
                for anti in ANTI_DEBUG_CALLS:
                    if anti in target:
                        findings.append({
                            "type": "anti_debug_call",
                            "addr": insn.get("addr"),
                            "detail": f"Call to anti-debug API '{ops[0]}'.",
                        })

    return {"anti_debug": findings} if findings else {}
