"""
Magic pattern / file format detection plugin.
Identifies common magic bytes and format signatures in instruction operands.
"""

MAGIC_PATTERNS = {
    0x7F454C46: "ELF header",
    0x4D5A: "MZ / PE header",
    0x504B0304: "ZIP/JAR header",
    0x89504E47: "PNG header",
    0xFFD8FF: "JPEG header",
    0xCAFEBABE: "Java class / Mach-O fat binary",
    0xFEEDFACE: "Mach-O 32-bit",
    0xFEEDFACF: "Mach-O 64-bit",
    0xDEADBEEF: "Debug / sentinel marker",
    0xCAFED00D: "Java pack200 marker",
    0xBAADF00D: "Windows heap debug marker",
}


def analyze(graph_store, func_addr: int) -> dict:
    """Detect magic byte patterns in function operands."""
    blocks = graph_store.fetch_basic_blocks(func_addr)
    findings = []

    for bb in blocks:
        insns = graph_store.fetch_block_instructions(bb)
        for insn in insns:
            ops = insn.get("operands") or []
            for op in ops:
                if not isinstance(op, str):
                    continue
                try:
                    val = int(op, 0) if op.startswith("0x") or op.startswith("-0x") else int(op)
                    val = val & 0xFFFFFFFF
                    if val in MAGIC_PATTERNS:
                        findings.append({
                            "type": "magic_pattern",
                            "addr": insn.get("addr"),
                            "detail": f"Magic pattern 0x{val:08X}: {MAGIC_PATTERNS[val]}.",
                        })
                except (ValueError, TypeError):
                    continue

    return {"magic_patterns": findings} if findings else {}
