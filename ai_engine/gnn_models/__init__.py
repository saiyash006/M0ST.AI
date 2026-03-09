"""
GNN model definitions for M0ST.
Provides Graph Attention Network (GAT), GraphSAGE, and GINE architectures
for structural analysis of control-flow graphs.

Re-exported from the legacy models package for backward compatibility.
"""

from typing import Optional

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.nn import (
        GATConv,
        SAGEConv,
        GINEConv,
        global_mean_pool,
        global_add_pool,
    )

    _TORCH_GEO_AVAILABLE = True
except ImportError:
    _TORCH_GEO_AVAILABLE = False


def is_available() -> bool:
    """Check if PyTorch Geometric is installed."""
    return _TORCH_GEO_AVAILABLE


# ---------------------------------------------------------------------------
# GAT-based CFG encoder
# ---------------------------------------------------------------------------

if _TORCH_GEO_AVAILABLE:

    class CFGGraphEncoder(nn.Module):
        """
        Graph Attention Network encoder for control-flow graphs.
        Produces per-node embeddings and a whole-graph embedding vector.
        """

        def __init__(
            self,
            in_channels: int = 64,
            hidden_channels: int = 128,
            out_channels: int = 256,
            num_heads: int = 4,
            num_layers: int = 3,
            dropout: float = 0.1,
            edge_dim: Optional[int] = None,
        ):
            super().__init__()
            self.num_layers = num_layers
            self.dropout = dropout

            self.convs = nn.ModuleList()
            self.norms = nn.ModuleList()

            self.convs.append(
                GATConv(in_channels, hidden_channels, heads=num_heads,
                        concat=True, dropout=dropout, edge_dim=edge_dim)
            )
            self.norms.append(nn.LayerNorm(hidden_channels * num_heads))

            for _ in range(num_layers - 2):
                self.convs.append(
                    GATConv(hidden_channels * num_heads, hidden_channels,
                            heads=num_heads, concat=True, dropout=dropout,
                            edge_dim=edge_dim)
                )
                self.norms.append(nn.LayerNorm(hidden_channels * num_heads))

            self.convs.append(
                GATConv(hidden_channels * num_heads, out_channels,
                        heads=1, concat=False, dropout=dropout,
                        edge_dim=edge_dim)
            )
            self.norms.append(nn.LayerNorm(out_channels))

            self.graph_proj = nn.Sequential(
                nn.Linear(out_channels, out_channels),
                nn.ReLU(),
                nn.Linear(out_channels, out_channels),
            )

        def forward(self, x, edge_index, edge_attr=None, batch=None):
            for i, (conv, norm) in enumerate(zip(self.convs, self.norms)):
                x = conv(x, edge_index, edge_attr=edge_attr)
                x = norm(x)
                if i < self.num_layers - 1:
                    x = F.elu(x)
                    x = F.dropout(x, p=self.dropout, training=self.training)

            node_embeddings = x

            if batch is None:
                batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
            graph_embedding = global_mean_pool(x, batch)
            graph_embedding = self.graph_proj(graph_embedding)

            return node_embeddings, graph_embedding

    class GraphSAGEEncoder(nn.Module):
        """GraphSAGE-based encoder for CFGs."""

        def __init__(self, in_channels: int = 64, hidden_channels: int = 128,
                     out_channels: int = 256, num_layers: int = 3, dropout: float = 0.1):
            super().__init__()
            self.num_layers = num_layers
            self.dropout = dropout
            self.convs = nn.ModuleList()
            self.norms = nn.ModuleList()

            self.convs.append(SAGEConv(in_channels, hidden_channels))
            self.norms.append(nn.LayerNorm(hidden_channels))
            for _ in range(num_layers - 2):
                self.convs.append(SAGEConv(hidden_channels, hidden_channels))
                self.norms.append(nn.LayerNorm(hidden_channels))
            self.convs.append(SAGEConv(hidden_channels, out_channels))
            self.norms.append(nn.LayerNorm(out_channels))

            self.graph_proj = nn.Sequential(
                nn.Linear(out_channels, out_channels),
                nn.ReLU(),
                nn.Linear(out_channels, out_channels),
            )

        def forward(self, x, edge_index, edge_attr=None, batch=None):
            for i, (conv, norm) in enumerate(zip(self.convs, self.norms)):
                x = conv(x, edge_index)
                x = norm(x)
                if i < self.num_layers - 1:
                    x = F.relu(x)
                    x = F.dropout(x, p=self.dropout, training=self.training)

            node_embeddings = x
            if batch is None:
                batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
            graph_embedding = global_mean_pool(x, batch)
            graph_embedding = self.graph_proj(graph_embedding)
            return node_embeddings, graph_embedding

    class GINEEncoder(nn.Module):
        """GINE encoder for CFGs with edge features."""

        def __init__(self, in_channels: int = 64, hidden_channels: int = 128,
                     out_channels: int = 256, edge_dim: int = 8,
                     num_layers: int = 3, dropout: float = 0.1):
            super().__init__()
            self.num_layers = num_layers
            self.dropout = dropout
            self.convs = nn.ModuleList()
            self.norms = nn.ModuleList()

            nn_first = nn.Sequential(
                nn.Linear(in_channels, hidden_channels), nn.ReLU(),
                nn.Linear(hidden_channels, hidden_channels))
            self.convs.append(GINEConv(nn_first, edge_dim=edge_dim))
            self.norms.append(nn.LayerNorm(hidden_channels))

            for _ in range(num_layers - 2):
                nn_mid = nn.Sequential(
                    nn.Linear(hidden_channels, hidden_channels), nn.ReLU(),
                    nn.Linear(hidden_channels, hidden_channels))
                self.convs.append(GINEConv(nn_mid, edge_dim=edge_dim))
                self.norms.append(nn.LayerNorm(hidden_channels))

            nn_last = nn.Sequential(
                nn.Linear(hidden_channels, out_channels), nn.ReLU(),
                nn.Linear(out_channels, out_channels))
            self.convs.append(GINEConv(nn_last, edge_dim=edge_dim))
            self.norms.append(nn.LayerNorm(out_channels))

            self.graph_proj = nn.Sequential(
                nn.Linear(out_channels, out_channels), nn.ReLU(),
                nn.Linear(out_channels, out_channels))

        def forward(self, x, edge_index, edge_attr=None, batch=None):
            for i, (conv, norm) in enumerate(zip(self.convs, self.norms)):
                x = conv(x, edge_index, edge_attr=edge_attr)
                x = norm(x)
                if i < self.num_layers - 1:
                    x = F.relu(x)
                    x = F.dropout(x, p=self.dropout, training=self.training)

            node_embeddings = x
            if batch is None:
                batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
            graph_embedding = global_add_pool(x, batch)
            graph_embedding = self.graph_proj(graph_embedding)
            return node_embeddings, graph_embedding

    def create_model(arch: str = "gat", in_channels: int = 64,
                     hidden_channels: int = 128, out_channels: int = 256,
                     **kwargs) -> nn.Module:
        """Factory to create a GNN model by architecture name."""
        arch = arch.lower()
        if arch == "gat":
            return CFGGraphEncoder(in_channels=in_channels,
                                   hidden_channels=hidden_channels,
                                   out_channels=out_channels, **kwargs)
        elif arch == "sage":
            return GraphSAGEEncoder(in_channels=in_channels,
                                    hidden_channels=hidden_channels,
                                    out_channels=out_channels, **kwargs)
        elif arch == "gine":
            return GINEEncoder(in_channels=in_channels,
                               hidden_channels=hidden_channels,
                               out_channels=out_channels, **kwargs)
        else:
            raise ValueError(f"Unknown GNN architecture: {arch}. Choose from: gat, sage, gine")

else:
    def create_model(*args, **kwargs):
        raise ImportError(
            "PyTorch Geometric is required for GNN models. "
            "Install with: pip install torch torch-geometric"
        )
