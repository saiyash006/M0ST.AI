#!/usr/bin/env python3
"""
M0ST — AI-Driven Multi-Agent Reverse Engineering Framework.

Architecture (7 layers):
  1. Interface         — CLI, API, command handlers
  2. AI Security Agents — 11 specialised analysis agents
  3. Orchestration      — Master planner + pipeline coordination
  4. Security Modules   — RE primitives + AI-assisted binary analysis
  5. AI Engine          — GNN/embedding/LLM inference + symbol recovery
  6. Knowledge          — PKG, embeddings, symbol DB, semantic index
  7. Data               — Binary corpus, analysis results, dataset pipeline

Entry point: always launches the interactive CLI.
If a binary path is given as argument, it is loaded automatically.
"""

import os
import sys

# Ensure the project root is on sys.path so imports work from any cwd.
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def main():
    # Interface layer re-exports the CLI; fall back to direct import
    try:
        from interface.cli import main as cli_main
    except ImportError:
        from ui.cli import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()
