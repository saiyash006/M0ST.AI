"""
M0ST Graph Agent — GNN-based structural analysis of control-flow graphs.

Converts CFG data from the PKG into PyTorch Geometric tensors,
runs a GNN model (GAT/GraphSAGE/GINE), and produces per-node and
whole-graph embedding vectors for downstream LLM fusion.
"""

import base64
import json
import math
from typing import Any, Dict, List, Optional, Tuple

from core.capabilities import Capability

try:
    import torch
    import numpy as np
    from torch_geometric.data import Data

    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False

try:
    from ai_engine.gnn_models import create_model, is_available as _gnn_available
except ImportError:
    _gnn_available = lambda: False
    create_model = None


_OPCODE_CATEGORIES = {
    "mov": 0, "lea": 0, "movzx": 0, "movsx": 0, "cmov": 0,
    "push": 1, "pop": 1,
    "add": 2, "sub": 2, "inc": 2, "dec": 2, "neg": 2, "adc": 2, "sbb": 2,
    "mul": 3, "imul": 3, "div": 3, "idiv": 3,
    "and": 4, "or": 4, "xor": 4, "not": 4, "shl": 4, "shr": 4, "sar": 4,
    "rol": 4, "ror": 4,
    "cmp": 5, "test": 5,
    "jmp": 6, "je": 6, "jne": 6, "jg": 6, "jge": 6, "jl": 6, "jle": 6,
    "ja": 6, "jb": 6, "jc": 6,
    "call": 7, "bl": 7, "blr": 7,
    "ret": 8, "retn": 8, "retq": 8, "leave": 8,
    "nop": 9,
    "syscall": 10, "int": 10, "svc": 10,
}
_NUM_OPCODE_CATS = 12


class GraphAgent:
    """GNN-based structural analysis agent for M0ST."""

    CAPABILITIES = {Capability.GNN_INFERENCE, Capability.STATIC_READ}

    def __init__(self, graph_store, model_path: Optional[str] = None,
                 arch: str = "gat", embedding_dim: int = 256, device: str = "cpu"):
        self.g = graph_store
        self.arch = arch
        self.embedding_dim = embedding_dim
        self.device = device
        self.model = None
        self._node_feature_dim = _NUM_OPCODE_CATS + 8

        if _TORCH_AVAILABLE and _gnn_available():
            try:
                self.model = create_model(
                    arch=arch, in_channels=self._node_feature_dim,
                    hidden_channels=128, out_channels=embedding_dim,
                )
                if model_path:
                    state_dict = torch.load(model_path, map_location=device)
                    self.model.load_state_dict(state_dict)
                self.model.to(device)
                self.model.eval()
            except Exception as e:
                print(f"[GraphAgent] Could not load GNN model: {e}")
                self.model = None

    def analyse_function(self, func_addr: int) -> Dict[str, Any]:
        blocks = self.g.fetch_basic_blocks(func_addr)
        edges = self.g.fetch_flow_edges(func_addr)
        if not blocks:
            return self._empty_result(func_addr)
        data = self._build_graph_data(func_addr, blocks, edges)
        if self.model is not None and _TORCH_AVAILABLE:
            return self._run_gnn(func_addr, data, blocks)
        else:
            return self._fallback_embedding(func_addr, data, blocks, edges)

    def analyse_all_functions(self) -> Dict[int, Dict[str, Any]]:
        results = {}
        for func in self.g.fetch_functions():
            addr = func.get("addr")
            if addr is None:
                continue
            results[addr] = self.analyse_function(addr)
        return results

    def get_graph_embedding_for_llm(self, func_addr: int) -> str:
        result = self.analyse_function(func_addr)
        return json.dumps(result.get("graph_embedding", []))

    def get_graph_embedding_b64(self, func_addr: int) -> str:
        result = self.analyse_function(func_addr)
        return result.get("graph_embedding_b64", "")

    def _build_graph_data(self, func_addr: int, blocks: List[int], edges: List[Tuple[int, int]]):
        block_to_idx = {bb: i for i, bb in enumerate(blocks)}
        node_features = []
        for bb in blocks:
            feat = self._compute_block_features(bb, blocks, edges)
            node_features.append(feat)
        src_list, dst_list = [], []
        for s, d in edges:
            if s in block_to_idx and d in block_to_idx:
                src_list.append(block_to_idx[s])
                dst_list.append(block_to_idx[d])
        if _TORCH_AVAILABLE:
            x = torch.tensor(node_features, dtype=torch.float32)
            if src_list:
                edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
            else:
                edge_index = torch.zeros((2, 0), dtype=torch.long)
            return Data(x=x, edge_index=edge_index)
        else:
            return {"x": node_features, "edge_index": [src_list, dst_list], "num_nodes": len(blocks)}

    def _compute_block_features(self, bb_addr: int, all_blocks: List[int],
                                all_edges: List[Tuple[int, int]]) -> List[float]:
        insns = self.g.fetch_block_instructions(bb_addr)
        hist = [0.0] * _NUM_OPCODE_CATS
        has_call = False
        has_branch = False
        for insn in insns:
            mnem = (insn.get("mnemonic") or "").lower()
            cat = _OPCODE_CATEGORIES.get(mnem, 11)
            hist[cat] += 1.0
            if cat == 7:
                has_call = True
            if cat == 6:
                has_branch = True
        total = sum(hist)
        if total > 0:
            hist = [h / total for h in hist]
        in_degree = sum(1 for _, d in all_edges if d == bb_addr)
        out_degree = sum(1 for s, _ in all_edges if s == bb_addr)
        is_entry = 1.0 if bb_addr == min(all_blocks) else 0.0
        is_exit = 1.0 if out_degree == 0 else 0.0
        log_addr = math.log2(bb_addr + 1) / 64.0 if bb_addr > 0 else 0.0
        structural = [
            min(len(insns) / 50.0, 1.0),
            min(in_degree / 10.0, 1.0),
            min(out_degree / 10.0, 1.0),
            is_entry, is_exit,
            1.0 if has_call else 0.0,
            1.0 if has_branch else 0.0,
            log_addr,
        ]
        return hist + structural

    def _run_gnn(self, func_addr: int, data, blocks: List[int]) -> Dict[str, Any]:
        with torch.no_grad():
            data = data.to(self.device)
            node_emb, graph_emb = self.model(data.x, data.edge_index)
            node_emb_list = node_emb.cpu().numpy().tolist()
            graph_emb_list = graph_emb.squeeze(0).cpu().numpy().tolist()
        graph_emb_bytes = json.dumps(graph_emb_list).encode("utf-8")
        graph_emb_b64 = base64.b64encode(graph_emb_bytes).decode("ascii")
        return {
            "func_addr": func_addr,
            "node_embeddings": node_emb_list,
            "graph_embedding": graph_emb_list,
            "graph_embedding_b64": graph_emb_b64,
            "block_addrs": blocks,
            "node_count": len(blocks),
            "edge_count": data.edge_index.size(1),
        }

    def _fallback_embedding(self, func_addr: int, data, blocks: List[int],
                            edges: List[Tuple[int, int]]) -> Dict[str, Any]:
        if isinstance(data, dict):
            features = data["x"]
        else:
            features = data.x.numpy().tolist() if _TORCH_AVAILABLE else data["x"]
        if features:
            dim = len(features[0])
            pooled = [0.0] * dim
            for feat in features:
                for i in range(dim):
                    pooled[i] += feat[i]
            pooled = [v / len(features) for v in pooled]
        else:
            pooled = [0.0] * self._node_feature_dim
        graph_emb = (pooled + [0.0] * self.embedding_dim)[: self.embedding_dim]
        graph_emb_bytes = json.dumps(graph_emb).encode("utf-8")
        graph_emb_b64 = base64.b64encode(graph_emb_bytes).decode("ascii")
        node_embeddings = [
            (feat + [0.0] * self.embedding_dim)[: self.embedding_dim]
            for feat in features
        ] if features else []
        return {
            "func_addr": func_addr,
            "node_embeddings": node_embeddings,
            "graph_embedding": graph_emb,
            "graph_embedding_b64": graph_emb_b64,
            "block_addrs": blocks,
            "node_count": len(blocks),
            "edge_count": len(edges),
        }

    def _empty_result(self, func_addr: int) -> Dict[str, Any]:
        empty_vec = [0.0] * self.embedding_dim
        return {
            "func_addr": func_addr,
            "node_embeddings": [],
            "graph_embedding": empty_vec,
            "graph_embedding_b64": base64.b64encode(
                json.dumps(empty_vec).encode("utf-8")
            ).decode("ascii"),
            "block_addrs": [],
            "node_count": 0,
            "edge_count": 0,
        }
