"""
Defines capability permissions for each agent.
Purpose:
- Prevent unauthorized operations.
- Maintain safe, deterministic multi-agent behavior.
"""

from enum import Enum, auto


class Capability(Enum):
    STATIC_READ = auto()
    STATIC_WRITE = auto()
    DYNAMIC_EXECUTE = auto()
    SEMANTIC_REASON = auto()
    VERIFY = auto()
    SNAPSHOT = auto()
    PLUGIN_ANALYSIS = auto()
    LLM_INFERENCE = auto()
    GNN_INFERENCE = auto()
    PSEUDOCODE = auto()
    PLANNING = auto()


def enforce_capability(agent, capability: Capability) -> bool:
    caps = getattr(agent.__class__, "CAPABILITIES", set())
    if capability not in caps:
        print(
            f"[Capability] Violation: {agent.__class__.__name__} lacks {capability.name}"
        )
        return False
    return True
