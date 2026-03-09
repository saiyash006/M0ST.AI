"""
Entropy analysis plugin.
Detects packed or encrypted sections by computing Shannon entropy
of instruction byte patterns across function basic blocks.
"""

import math
from collections import Counter
from typing import Dict, List


def _shannon_entropy(data: List[int]) -> float:
    """Compute Shannon entropy of a list of byte values (0-255)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def analyze(graph_store, func_addr: int) -> dict:
    """
    Compute entropy of instruction operand bytes in a function.

    High entropy (>7.0) in code regions suggests packing, encryption,
    or obfuscation. This is a common technique in malware analysis.

    Returns a dict with entropy score and assessment.
    """
    blocks = graph_store.fetch_basic_blocks(func_addr)
    if not blocks:
        return {}

    byte_values: List[int] = []
    total_insns = 0

    for bb in blocks:
        insns = graph_store.fetch_block_instructions(bb)
        for insn in insns:
            total_insns += 1
            addr = insn.get("addr")
            if isinstance(addr, int):
                # Use address bytes as proxy for code distribution
                for shift in range(0, 64, 8):
                    b = (addr >> shift) & 0xFF
                    if b != 0:
                        byte_values.append(b)

            # Also extract immediates from operands as byte patterns
            ops = insn.get("operands") or []
            for op in ops:
                if not isinstance(op, str):
                    continue
                try:
                    if op.startswith("0x") or op.startswith("-0x"):
                        val = int(op, 16)
                    elif op.lstrip("-").isdigit():
                        val = int(op)
                    else:
                        continue
                    val = abs(val) & 0xFFFFFFFF
                    for shift in range(0, 32, 8):
                        b = (val >> shift) & 0xFF
                        byte_values.append(b)
                except (ValueError, TypeError):
                    continue

    if len(byte_values) < 16:
        return {}

    entropy = _shannon_entropy(byte_values)

    findings = []

    if entropy > 7.0:
        findings.append({
            "type": "high_entropy_function",
            "detail": (
                f"Function has high entropy ({entropy:.2f}/8.0) — "
                f"likely packed, encrypted, or obfuscated."
            ),
            "entropy": round(entropy, 3),
            "sample_size": len(byte_values),
        })
    elif entropy > 6.0:
        findings.append({
            "type": "elevated_entropy_function",
            "detail": (
                f"Function has elevated entropy ({entropy:.2f}/8.0) — "
                f"may contain encoded data or complex arithmetic."
            ),
            "entropy": round(entropy, 3),
            "sample_size": len(byte_values),
        })

    # Detect uniform byte distribution (potential encrypted blob)
    if byte_values:
        counts = Counter(byte_values)
        unique_ratio = len(counts) / 256.0
        if unique_ratio > 0.7 and entropy > 6.5:
            findings.append({
                "type": "uniform_byte_distribution",
                "detail": (
                    f"Byte distribution covers {len(counts)}/256 unique values "
                    f"({unique_ratio:.0%}) — potential encrypted/compressed data."
                ),
                "unique_bytes": len(counts),
            })

    return {"entropy": findings} if findings else {}
