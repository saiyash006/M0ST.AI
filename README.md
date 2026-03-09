# M0ST — AI-Driven Multi-Agent Reverse Engineering Framework

**M0ST** (formerly SPIDER-AI) is a next-generation, research-grade multi-agent system for automated binary reverse engineering. Built on a **7-layer architecture**, it combines classical static/dynamic analysis with GNN-based structural reasoning, LLM-powered semantic inference, and a Program Knowledge Graph (PKG) to produce high-quality function names, type annotations, pseudocode, vulnerability reports, and malware classifications.

---

## Features

- **7-layer architecture** — Interface → AI Security Agents → Orchestration → Security Modules → AI Engine → Knowledge → Data
- **Program Knowledge Graph (PKG)** — centralized knowledge store linking functions, blocks, variables, types, and analysis results
- **AI-powered analysis** — GNN graph embeddings + LLM inference for function naming, type recovery, and semantic explanation
- **Symbol recovery** — 3-stage function name prediction (heuristic → embedding similarity → LLM)
- **Deobfuscation engine** — detects control-flow flattening, opaque predicates, junk code, packers, VM-based obfuscation
- **Vulnerability detection** — unsafe calls, stack overflow, format strings, UAF, integer overflow, LLM-based detection
- **Malware classification** — suspicious API categorization, risk scoring (0.0–1.0)
- **11 AI security agents** — static, graph (GNN), LLM, pseudocode, dynamic, verifier, Z3, semantic, heuristics, static post-processing, LLM semantic
- **Planner orchestrator** — intelligent 10-stage pipeline that decides which agents to invoke
- **Plugin system** — extensible analysis via dynamically loaded plugins (anti-debug, crypto, entropy, magic patterns, string decoding), PKG-integrated
- **Binary embedding engine** — CFG → GNN → embedding pipeline with cosine similarity search
- **Dataset pipeline** — training data collection (function embeddings, vulnerability labels, symbol ground truth, deobfuscation pairs)
- **Pseudocode extraction** — Ghidra / radare2 decompilation with normalization and metadata extraction
- **Constraint solving** — Z3-powered branch feasibility checking and infeasible edge pruning
- **JSON export** — full analysis export for interoperability and reporting
- **Snapshot system** — save, load, list, and diff analysis states
- **Graceful degradation** — every AI/ML component is optional; falls back to classical heuristics
- **Cross-platform** — Linux and Windows (dynamic tracing Linux-only)
- **Docker support** — one-command deployment

---

## Quick Start

```bash
# 1. Set up
python -m venv .venv
source .venv/bin/activate    # Linux
# .venv\Scripts\activate     # Windows
pip install -r requirements.txt

# 2. Run
python main.py                        # Interactive CLI
python main.py path/to/binary         # Direct analysis

# 3. Docker
cd docker && docker compose up -d
```

See [SETUP.md](SETUP.md) for detailed installation instructions.

---

## CLI Commands

### Core Commands

| Command                        | Description                                        |
| ------------------------------ | -------------------------------------------------- |
| `load <binary>`                | Analyze a binary                                   |
| `list funcs`                   | List discovered functions                          |
| `info <addr>`                  | Function details                                   |
| `blocks / insns / edges`       | CFG exploration                                    |
| `explain [level] <addr>`       | Semantic summary (simple/medium/deep)              |
| `pseudocode <addr>`            | Decompiled pseudocode                              |
| `complexity [addr]`            | Cyclomatic complexity metrics                      |
| `verify`                       | Run verifier (branch feasibility, unsafe patterns) |
| `export <path>`                | Export analysis to JSON                            |
| `plugins list / run`           | Manage analysis plugins                            |
| `snapshot save/list/show/diff` | Manage analysis snapshots                          |
| `status`                       | Check tool availability                            |

### AI Commands

| Command              | Description                       |
| -------------------- | --------------------------------- |
| `ai name <addr>`     | LLM-based function naming         |
| `ai explain <addr>`  | LLM-based function summary        |
| `ai types <addr>`    | LLM-based type inference          |
| `ai refine <addr>`   | Integrated GNN + LLM analysis     |
| `ai full`            | Full multi-agent AI pipeline      |
| `ai vulns <addr>`    | LLM-based vulnerability detection |
| `ai annotate <addr>` | LLM-based code annotation         |

---

## Project Structure

```
├── main.py                       # Entry point
├── config.yml                    # Configuration (LLM, GNN, tools)
│
├── interface/                    # Layer 1: Interface
│   ├── cli/                      #   CLI entry point
│   ├── api/                      #   FastAPI REST server
│   └── commands/                 #   Command handlers
│
├── ai_security_agents/           # Layer 2: AI Security Agents (11 agents)
│   ├── static_agent.py           #   radare2 disassembly
│   ├── graph_agent.py            #   GNN structural analysis
│   ├── llm_agent.py              #   LLM wrapper (multi-provider)
│   ├── pseudocode_agent.py       #   Ghidra/r2 decompilation
│   ├── llm_semantic_agent.py     #   AI-powered semantic reasoning
│   ├── dynamic_agent.py          #   GDB-based dynamic tracing
│   ├── verifier_agent.py         #   Z3 verification
│   ├── z3_agent.py               #   Constraint solver
│   ├── semantic_agent.py         #   Rule-based explanation
│   ├── heuristics_agent.py       #   Classical pattern matching
│   └── static_post.py            #   CFG cleanup
│
├── orchestration/                # Layer 3: Orchestration
│   ├── master_agent.py           #   Pipeline controller
│   └── planner_agent.py          #   10-stage intelligent planner
│
├── security_modules/             # Layer 4: Security Modules
│   ├── reverse_engineering/      #   Disassembly, CFG, pseudocode,
│   │                             #   type inference, deobfuscation
│   └── ai_assisted_binary_analysis/  # Vulnerability detection,
│                                 #   malware classification
│
├── ai_engine/                    # Layer 5: AI Engine
│   ├── gnn_models/               #   GAT, GraphSAGE, GINE
│   ├── embedding_models/         #   Binary embedding pipeline
│   ├── llm_inference/            #   Multi-provider LLM wrapper
│   ├── symbol_recovery/          #   Function/variable name recovery
│   └── training/                 #   Model fine-tuning
│
├── knowledge/                    # Layer 6: Knowledge
│   ├── program_graph/            #   Program Knowledge Graph (PKG)
│   ├── embeddings/               #   Embedding vector store
│   ├── symbol_database/          #   Recovered symbol store
│   └── semantic_index/           #   Semantic metadata index
│
├── data/                         # Layer 7: Data
│   ├── binaries/                 #   Binary repository
│   ├── analysis_results/         #   Persisted analysis outputs
│   └── datasets/                 #   Training dataset pipeline
│
├── core/                         # Config, capabilities, events, IR
├── storage/                      # In-memory graph, SQLite, snapshots
├── plugins/                      # Dynamic analysis plugins
├── analysis/                     # Complexity, export, constraint passes
├── ui/                           # Interactive CLI implementation
├── docker/                       # Docker deployment
└── tests/                        # Test binaries and unit tests
```

---

## Documentation

- **[SETUP.md](SETUP.md)** — Installation guide (Linux + Windows)
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System design and data flow
- **[PLUGINS.md](PLUGINS.md)** — Plugin development guide

---

## Requirements

- Python 3.10+
- Optional: radare2, GDB (Linux), z3-solver
- Optional AI: OpenAI / Anthropic / Mistral API key (or local Ollama)
- Optional ML: PyTorch + PyTorch Geometric (for GNN embeddings)

All optional dependencies have graceful fallbacks — M0ST works fully with zero external services.
