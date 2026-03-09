"""
CLI interface — M0ST Layer 1 entry point.

Re-exports the CLI main() from the legacy ui module while
routing through the new M0ST architecture layers via the
updated orchestration layer.
"""

from ui.cli import main

__all__ = ["main"]
