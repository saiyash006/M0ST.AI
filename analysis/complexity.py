"""
Cyclomatic complexity analysis for functions in the graph store.
Uses the CFG (edges, nodes) to compute complexity metrics.
"""

from typing import Dict, List, Set, Tuple


def cyclomatic_complexity(graph_store, func_addr: int) -> Dict:
    """
    Compute cyclomatic complexity for a single function.

    Formula: M = E - N + 2P
      E = number of edges
      N = number of nodes (basic blocks)
      P = number of connected components (1 for a single function)

    Returns a dict with the complexity score and classification.
    """
    blocks = graph_store.fetch_basic_blocks(func_addr)
    edges = graph_store.fetch_flow_edges(func_addr)

    n = len(blocks)
    e = len(edges)
    p = 1  # single function = 1 connected component

    if n == 0:
        return {
            "func_addr": func_addr,
            "nodes": 0,
            "edges": 0,
            "complexity": 0,
            "classification": "empty",
        }

    m = e - n + 2 * p

    if m <= 4:
        classification = "simple"
    elif m <= 10:
        classification = "moderate"
    elif m <= 20:
        classification = "complex"
    elif m <= 50:
        classification = "very_complex"
    else:
        classification = "untestable"

    return {
        "func_addr": func_addr,
        "nodes": n,
        "edges": e,
        "complexity": m,
        "classification": classification,
    }


def all_complexities(graph_store) -> List[Dict]:
    """Compute cyclomatic complexity for every function in the graph store."""
    results = []
    for func in graph_store.fetch_functions():
        addr = func.get("addr")
        if addr is None:
            continue
        results.append(cyclomatic_complexity(graph_store, addr))
    return sorted(results, key=lambda r: r["complexity"], reverse=True)
