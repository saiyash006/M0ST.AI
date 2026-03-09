"""
API interface — M0ST Layer 1 REST endpoint (stub).

Future: FastAPI-based REST API for programmatic access
to the analysis pipeline.
"""

from typing import Any, Dict, Optional


class APIServer:
    """
    REST API server stub.

    Planned endpoints:
    - POST /analyze          — Start binary analysis
    - GET  /functions        — List discovered functions
    - GET  /function/{addr}  — Get function details
    - GET  /cfg/{addr}       — Get CFG data
    - GET  /pseudocode/{addr} — Get pseudocode
    - POST /ai/name          — AI function naming
    - POST /ai/explain       — AI function explanation
    - POST /ai/vulns         — AI vulnerability detection
    - GET  /snapshots        — List analysis snapshots
    """

    def __init__(self, master_agent=None):
        self.master = master_agent

    def start(self, host: str = "0.0.0.0", port: int = 8080):
        """Start the API server (requires FastAPI + Uvicorn)."""
        try:
            from fastapi import FastAPI
            import uvicorn
        except ImportError:
            print("[API] FastAPI or Uvicorn not installed. Install with:")
            print("      pip install fastapi uvicorn")
            return

        app = FastAPI(title="M0ST Binary Analysis API", version="2.0.0")

        @app.get("/health")
        def health():
            return {"status": "ok"}

        @app.get("/functions")
        def list_functions():
            if self.master is None:
                return {"error": "No analysis loaded"}
            funcs = self.master.graph_store.fetch_functions()
            return {"functions": funcs}

        uvicorn.run(app, host=host, port=port)
