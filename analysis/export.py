"""
Export analysis results to structured JSON for reporting and interoperability.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def export_analysis_json(
    graph_store,
    output_path: str,
    binary_path: Optional[str] = None,
    include_instructions: bool = True,
) -> str:
    """
    Export the full analysis state from the graph store to a JSON file.

    Args:
        graph_store: The populated graph store instance.
        output_path: Path to write the JSON report to.
        binary_path: Optional path of the analyzed binary.
        include_instructions: Whether to include per-block instruction details.

    Returns:
        The absolute path of the written report file.
    """
    report: Dict[str, Any] = {
        "meta": {
            "tool": "M0ST",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "binary_path": binary_path,
        },
        "functions": [],
    }

    functions = graph_store.fetch_functions()
    for func in functions:
        addr = func.get("addr")
        if addr is None:
            continue

        blocks_addrs = graph_store.fetch_basic_blocks(addr)
        edges = graph_store.fetch_flow_edges(addr)

        func_entry: Dict[str, Any] = {
            "name": func.get("name", f"sub_{addr:x}"),
            "addr": addr,
            "addr_hex": f"0x{addr:x}",
            "block_count": len(blocks_addrs),
            "edge_count": len(edges),
            "edges": [{"src": f"0x{s:x}", "dst": f"0x{d:x}"} for s, d in edges],
            "properties": {
                k: v for k, v in func.items() if k not in ("name", "addr")
            },
        }

        if include_instructions:
            blocks = []
            for bb in blocks_addrs:
                insns = graph_store.fetch_block_instructions(bb)
                blocks.append({
                    "addr": bb,
                    "addr_hex": f"0x{bb:x}",
                    "instructions": [
                        {
                            "addr": f"0x{insn['addr']:x}",
                            "mnemonic": insn.get("mnemonic", ""),
                            "operands": insn.get("operands", []),
                        }
                        for insn in insns
                    ],
                })
            func_entry["blocks"] = blocks

        report["functions"].append(func_entry)

    # Verification results
    try:
        vr = graph_store.get_verification_results()
        if vr:
            report["verification"] = vr
    except Exception:
        pass

    # Semantic summaries
    try:
        ss = graph_store.get_semantic_summaries()
        if ss:
            report["semantic_summaries"] = ss
    except Exception:
        pass

    report["summary"] = {
        "total_functions": len(functions),
        "total_blocks": sum(
            len(graph_store.fetch_basic_blocks(f.get("addr", 0)))
            for f in functions
            if f.get("addr") is not None
        ),
        "total_edges": sum(
            len(graph_store.fetch_flow_edges(f.get("addr", 0)))
            for f in functions
            if f.get("addr") is not None
        ),
    }

    # Ensure output directory exists
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    abs_path = os.path.abspath(output_path)
    with open(abs_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    return abs_path
