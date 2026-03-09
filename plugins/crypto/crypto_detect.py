"""
Crypto pattern detection plugin.
Identifies common cryptographic constants and instruction patterns.
"""

# Well-known crypto constants (partial first dwords)
CRYPTO_CONSTANTS = {
    0x67452301: "MD5/SHA-1 init",
    0xEFCDAB89: "MD5/SHA-1 init",
    0x98BADCFE: "MD5/SHA-1 init",
    0x10325476: "MD5/SHA-1 init",
    0x6A09E667: "SHA-256 init",
    0xBB67AE85: "SHA-256 init",
    0x3C6EF372: "SHA-256 init",
    0xA54FF53A: "SHA-256 init",
    0x27B70A85: "SHA-256 round constant",
    0x9E3779B9: "TEA / golden ratio",
    0x61707865: "ChaCha20 constant",
    0x3320646E: "ChaCha20 constant",
    0x79622D32: "ChaCha20 constant",
    0x6B206574: "ChaCha20 constant",
}

CRYPTO_OPS = {"xor", "rol", "ror", "shl", "shr", "sar", "and", "or", "not"}


def analyze(graph_store, func_addr: int) -> dict:
    """Detect crypto patterns in a function."""
    blocks = graph_store.fetch_basic_blocks(func_addr)
    findings = []
    crypto_op_count = 0
    total_insn_count = 0

    for bb in blocks:
        insns = graph_store.fetch_block_instructions(bb)
        for insn in insns:
            mnem = (insn.get("mnemonic") or "").lower()
            ops = insn.get("operands") or []
            total_insn_count += 1

            if mnem in CRYPTO_OPS:
                crypto_op_count += 1

            # Check for known crypto constants in immediates
            for op in ops:
                if not isinstance(op, str):
                    continue
                try:
                    val = int(op, 0) if op.startswith("0x") or op.startswith("-0x") else int(op)
                    val = val & 0xFFFFFFFF  # mask to 32-bit
                    if val in CRYPTO_CONSTANTS:
                        findings.append({
                            "type": "crypto_constant",
                            "addr": insn.get("addr"),
                            "detail": f"Known crypto constant 0x{val:08x} ({CRYPTO_CONSTANTS[val]}).",
                        })
                except (ValueError, TypeError):
                    continue

    if total_insn_count > 0 and crypto_op_count / total_insn_count > 0.3:
        findings.append({
            "type": "crypto_heavy_function",
            "detail": f"Function has high ratio of crypto-style ops ({crypto_op_count}/{total_insn_count}).",
        })

    return {"crypto": findings} if findings else {}
