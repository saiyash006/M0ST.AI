"""
Defines system event/stage types for inter-agent communication.
Purpose:
- Standardized stage names used by the pipeline orchestrator.
- Ensures agents interact without direct coupling.

Note: The old Redis-based event bus has been removed in M0ST v2.
These constants are retained for logging and stage tracking.
"""


class Events:
    # Pipeline stage markers
    STATIC_ANALYSIS_COMPLETE = "static_complete"
    GNN_ANALYSIS_COMPLETE = "gnn_complete"
    PSEUDOCODE_READY = "pseudocode_ready"
    LLM_INFERENCE_COMPLETE = "llm_complete"
    DYNAMIC_TRACE_READY = "dynamic_trace"
    SEMANTIC_SUMMARY_READY = "semantic_ready"
    VERIFY_REQUEST = "verify_request"
    VERIFY_RESULT = "verify_result"
    PLANNING_COMPLETE = "planning_complete"
    AI_PIPELINE_COMPLETE = "ai_pipeline_complete"

