"""
String decoder plugin.
Identifies string construction patterns and XOR-encoded string decoding loops.
"""

import re


def analyze(graph_store, func_addr: int) -> dict:
    """Detect string-related patterns in a function."""
    blocks = graph_store.fetch_basic_blocks(func_addr)
    findings = []

    for bb in blocks:
        insns = graph_store.fetch_block_instructions(bb)
        for insn in insns:
            mnem = (insn.get("mnemonic") or "").lower()
            ops = insn.get("operands") or []

            # Detect calls to string functions
            if mnem in {"call", "bl", "blr"} and ops:
                target = ops[0].lower()
                string_funcs = {"strlen", "strcmp", "strncmp", "strstr",
                                "strcpy", "strncpy", "strcat", "strncat",
                                "memcpy", "memset", "memmove", "memcmp"}
                for sf in string_funcs:
                    if sf in target:
                        findings.append({
                            "type": "string_api_call",
                            "addr": insn.get("addr"),
                            "detail": f"Call to string function '{ops[0]}'.",
                        })

            # Detect XOR with small constant (potential string decoding)
            if mnem == "xor" and len(ops) >= 2:
                # If XOR with a small non-zero immediate, possible decode
                op1 = ops[1] if len(ops) > 1 else ""
                if isinstance(op1, str):
                    m = re.search(r"0x([0-9a-fA-F]+)", op1)
                    if m:
                        try:
                            val = int(m.group(1), 16)
                            if 0 < val < 256:
                                findings.append({
                                    "type": "xor_decode_candidate",
                                    "addr": insn.get("addr"),
                                    "detail": f"XOR with byte constant 0x{val:02x} — possible string decode.",
                                })
                        except ValueError:
                            pass

    return {"string_decoder": findings} if findings else {}
