"""
CFG Recovery module — Extracts and normalizes Control Flow Graphs.

Provides routines for building CFGs from disassembly output,
normalizing edges, and integrating with the Program Knowledge Graph.
"""

from typing import Any, Dict, List, Set, Tuple


class CFGRecovery:
    """
    Builds and normalizes CFGs from raw disassembly data.
    """

    def build_cfg(
        self,
        blocks: List[Dict[str, Any]],
    ) -> Tuple[List[int], List[Tuple[int, int]]]:
        """
        Build a CFG from radare2 block info (afbj output).

        Returns (block_addresses, edges).
        """
        block_addrs = []
        edges = []

        for block in blocks:
            addr = block.get("addr")
            if addr is None:
                continue
            block_addrs.append(addr)

            # Jump target
            jump = block.get("jump")
            if jump is not None:
                edges.append((addr, jump))

            # Fall-through target
            fail = block.get("fail")
            if fail is not None:
                edges.append((addr, fail))

        return block_addrs, edges

    def normalize_edges(
        self,
        block_addrs: List[int],
        edges: List[Tuple[int, int]],
    ) -> List[Tuple[int, int]]:
        """Remove edges pointing to addresses not in the block set."""
        valid = set(block_addrs)
        return [(s, d) for s, d in edges if s in valid and d in valid]

    def find_entry_block(self, func_addr: int, block_addrs: List[int]) -> int:
        """Determine the entry block for a function."""
        if func_addr in block_addrs:
            return func_addr
        return min(block_addrs) if block_addrs else func_addr

    def compute_predecessors(
        self, block_addrs: List[int], edges: List[Tuple[int, int]]
    ) -> Dict[int, List[int]]:
        """Compute predecessor map."""
        preds: Dict[int, List[int]] = {b: [] for b in block_addrs}
        for src, dst in edges:
            if dst in preds:
                preds[dst].append(src)
        return preds

    def compute_successors(
        self, block_addrs: List[int], edges: List[Tuple[int, int]]
    ) -> Dict[int, List[int]]:
        """Compute successor map."""
        succs: Dict[int, List[int]] = {b: [] for b in block_addrs}
        for src, dst in edges:
            if src in succs:
                succs[src].append(dst)
        return succs

    def find_reachable(
        self, entry: int, succs: Dict[int, List[int]]
    ) -> Set[int]:
        """BFS to find all reachable blocks from entry."""
        visited: Set[int] = set()
        queue = [entry]
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            for nxt in succs.get(node, []):
                if nxt not in visited:
                    queue.append(nxt)
        return visited

    def to_pkg_format(
        self,
        func_addr: int,
        func_name: str,
        block_addrs: List[int],
        edges: List[Tuple[int, int]],
        block_instructions: Dict[int, List[Dict]],
    ) -> Dict[str, Any]:
        """
        Convert CFG data into a format suitable for importing
        into the Program Knowledge Graph (PKG).
        """
        return {
            "function": {
                "addr": func_addr,
                "name": func_name,
            },
            "blocks": block_addrs,
            "edges": edges,
            "instructions": block_instructions,
        }
