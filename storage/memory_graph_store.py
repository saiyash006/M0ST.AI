"""
In-memory graph store — the primary graph backend for M0ST.
Stores functions, basic blocks, instructions, and edges in Python dicts.
"""

import json
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


class MemoryGraphStore:
    """
    Pure-Python in-memory graph store.
    Provides the same public API as GraphStore so agents work unchanged.
    """

    def __init__(self):
        # Nodes
        self._functions: Dict[int, Dict[str, Any]] = {}          # addr -> {name, addr, ...}
        self._basic_blocks: Dict[int, Dict[str, Any]] = {}       # addr -> {addr, ...}
        self._instructions: Dict[int, Dict[str, Any]] = {}       # addr -> {addr, mnemonic, operands}
        self._runs: Dict[str, Dict[str, Any]] = {}               # run_id -> {id, binary_path}

        # Relationships
        self._func_to_blocks: Dict[int, Set[int]] = defaultdict(set)  # func_addr -> {bb_addr}
        self._block_to_insns: Dict[int, Set[int]] = defaultdict(set)  # bb_addr -> {insn_addr}
        self._flow_edges: Set[Tuple[int, int]] = set()
        self._call_edges: Set[Tuple[int, int]] = set()
        self._runtime_flow: List[Dict] = []
        self._executes: List[Dict] = []
        self._syscall_events: List[Dict] = []
        self._suspect_edges: Set[Tuple[int, int]] = set()

        # Metadata singletons
        self._verification_results: Optional[Dict] = None
        self._semantic_summaries: Optional[Dict] = None

    # ---------------------------
    # Node Creation
    # ---------------------------

    def create_function(self, name: str, addr: int):
        self._functions[addr] = {"name": name, "addr": addr}

    def create_basic_block(self, func_addr: int, bb_addr: int):
        self._basic_blocks[bb_addr] = {"addr": bb_addr}
        self._func_to_blocks[func_addr].add(bb_addr)

    def create_instruction(self, bb_addr: int, addr: int, mnemonic: str, operands: List[str]):
        self._instructions[addr] = {
            "addr": addr,
            "mnemonic": mnemonic,
            "operands": list(operands),
        }
        self._block_to_insns[bb_addr].add(addr)

    # ---------------------------
    # Relationships
    # ---------------------------

    def add_flow_edge(self, src_bb: int, dst_bb: int):
        self._flow_edges.add((src_bb, dst_bb))

    def add_call_edge(self, src_func: int, dst_func: int):
        self._call_edges.add((src_func, dst_func))

    # ---------------------------
    # Queries
    # ---------------------------

    def fetch_functions(self) -> List[Dict]:
        return sorted(self._functions.values(), key=lambda f: f["addr"])

    def fetch_basic_blocks(self, func_addr: int) -> List[int]:
        return sorted(self._func_to_blocks.get(func_addr, set()))

    def fetch_all_basic_blocks(self) -> List[int]:
        return sorted(self._basic_blocks.keys())

    def fetch_flow_edges(self, func_addr: int) -> List[Tuple[int, int]]:
        block_set = self._func_to_blocks.get(func_addr, set())
        return sorted(
            (s, d) for s, d in self._flow_edges
            if s in block_set and d in block_set
        )

    def fetch_all_flow_edges(self) -> List[Tuple[int, int]]:
        return sorted(self._flow_edges)

    def fetch_flow_edges_from(self, src_bb: int) -> List[Tuple[int, int]]:
        return sorted((s, d) for s, d in self._flow_edges if s == src_bb)

    def fetch_block_instructions(self, bb_addr: int) -> List[Dict]:
        insn_addrs = self._block_to_insns.get(bb_addr, set())
        return sorted(
            [self._instructions[a] for a in insn_addrs if a in self._instructions],
            key=lambda i: i["addr"],
        )

    # ---------------------------
    # Heuristics / Properties
    # ---------------------------

    def mark_loop_header(
        self,
        bb_addr: int,
        loop_body=None,
        back_edges=None,
        loop_depth=None,
        crypto_constant_time=None,
    ):
        if bb_addr in self._basic_blocks:
            self._basic_blocks[bb_addr].update({
                "loop_header": True,
                "loop_body": loop_body,
                "loop_back_edges": back_edges,
                "loop_depth": loop_depth,
                "crypto_constant_time": crypto_constant_time,
            })

    def set_function_properties(self, func_addr: int, props: Dict):
        if func_addr in self._functions:
            self._functions[func_addr].update(props)

    def set_plugin_facts(self, func_addr: int, facts: Dict):
        if func_addr in self._functions:
            self._functions[func_addr]["plugin_facts"] = json.dumps(facts)

    def set_switch_info(self, func_addr: int, header_bb: int, cases: List[int]):
        if header_bb in self._basic_blocks:
            self._basic_blocks[header_bb].update({
                "switch_header": True,
                "switch_cases": cases,
            })

    def remove_flow_edge(self, src_bb: int, dst_bb: int):
        self._flow_edges.discard((src_bb, dst_bb))

    # ---------------------------
    # Dynamic tracing
    # ---------------------------

    def create_run(self, run_id: str, binary_path: str):
        self._runs[run_id] = {"id": run_id, "binary_path": binary_path}

    def get_latest_run(self) -> Optional[Dict]:
        if not self._runs:
            return None
        return list(self._runs.values())[-1]

    def add_executes_edge(
        self,
        run_id: str,
        bb_addr: int,
        seq: int,
        pc: int,
        next_pc: int,
        regs: Dict,
    ):
        self._executes.append({
            "run_id": run_id,
            "bb_addr": bb_addr,
            "seq": seq,
            "pc": pc,
            "next_pc": next_pc,
            "regs": regs,
        })

    def add_runtime_flow(
        self,
        run_id: str,
        src_bb: int,
        dst_bb: int,
        seq: int,
        pc: int,
        next_pc: int,
        regs: Dict,
    ):
        self._runtime_flow.append({
            "run_id": run_id,
            "src_bb": src_bb,
            "dst_bb": dst_bb,
            "seq": seq,
            "pc": pc,
            "next_pc": next_pc,
            "regs": regs,
        })

    def add_syscall_event(
        self,
        run_id: str,
        seq: int,
        pc: int,
        syscall_number: int,
        args: List,
    ):
        safe_args = [a if isinstance(a, int) else 0 for a in args if a is not None]
        self._syscall_events.append({
            "run_id": run_id,
            "seq": seq,
            "pc": pc,
            "syscall_number": syscall_number,
            "args": safe_args,
        })

    def fetch_runtime_flow_edges(self) -> List[Tuple[int, int]]:
        seen: Set[Tuple[int, int]] = set()
        for entry in self._runtime_flow:
            seen.add((entry["src_bb"], entry["dst_bb"]))
        return sorted(seen)

    def fetch_executed_blocks(self) -> List[int]:
        seen: Set[int] = set()
        for entry in self._executes:
            seen.add(entry["bb_addr"])
        return sorted(seen)

    def mark_flow_edge_suspect(self, src_bb: int, dst_bb: int):
        self._suspect_edges.add((src_bb, dst_bb))

    # ---------------------------
    # Verification / Semantic
    # ---------------------------

    def set_verification_results(self, results: Dict):
        self._verification_results = results

    def get_verification_results(self) -> Optional[Dict]:
        return self._verification_results

    def set_semantic_summaries(self, summaries: Dict):
        self._semantic_summaries = summaries

    def get_semantic_summaries(self) -> Optional[Dict]:
        return self._semantic_summaries

    # ---------------------------
    # Maintenance
    # ---------------------------

    def clear_graph(self):
        self._functions.clear()
        self._basic_blocks.clear()
        self._instructions.clear()
        self._runs.clear()
        self._func_to_blocks.clear()
        self._block_to_insns.clear()
        self._flow_edges.clear()
        self._call_edges.clear()
        self._runtime_flow.clear()
        self._executes.clear()
        self._syscall_events.clear()
        self._suspect_edges.clear()
        self._verification_results = None
        self._semantic_summaries = None

    def close(self):
        pass

    def session(self):
        return None
