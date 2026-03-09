"""
M0ST LLM Agent — Wrapper for LLM-based reverse engineering inference.

Supports OpenAI, Anthropic, Mistral, and local LLM backends.
Enhanced context construction with PKG-aware prompting (M0ST Step 6).
"""

import json
import os
from typing import Any, Dict, List, Optional

from core.capabilities import Capability

try:
    import openai
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False

try:
    import anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False


class LLMAgent:
    """LLM-based reasoning agent for reverse engineering tasks."""

    CAPABILITIES = {Capability.LLM_INFERENCE, Capability.SEMANTIC_REASON}
    TOOL_REGISTRY: Dict[str, Any] = {}

    def __init__(self, provider: str = "openai", model: Optional[str] = None,
                 api_key: Optional[str] = None, api_base: Optional[str] = None,
                 temperature: float = 0.2, max_tokens: int = 2048):
        self.provider = provider.lower()
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.model = model or self._default_model()
        self.api_key = api_key or self._resolve_api_key()
        self.api_base = api_base
        self.client = self._init_client()

    # ── Public inference methods ───────────────────────────────────────────

    def infer_function_name(self, disassembly: str = "", pseudocode: str = "",
                            metadata: Optional[Dict] = None,
                            gnn_embedding: Optional[List[float]] = None) -> Dict[str, Any]:
        prompt = self._build_prompt(
            task="infer_function_name",
            instruction='Analyze the following reverse-engineered function and suggest a descriptive function name. Return JSON with keys: "name" (string), "confidence" (0.0-1.0), "reasoning" (string).',
            disassembly=disassembly, pseudocode=pseudocode,
            metadata=metadata, gnn_embedding=gnn_embedding,
        )
        return self._query_json(prompt)

    def infer_variable_names(self, disassembly: str = "", pseudocode: str = "",
                             metadata: Optional[Dict] = None,
                             gnn_embedding: Optional[List[float]] = None) -> Dict[str, Any]:
        prompt = self._build_prompt(
            task="infer_variable_names",
            instruction='Analyze the following code and suggest descriptive names for variables (registers, stack slots). Return JSON with key "variables": list of {"original": str, "suggested": str, "type_hint": str, "reasoning": str}.',
            disassembly=disassembly, pseudocode=pseudocode,
            metadata=metadata, gnn_embedding=gnn_embedding,
        )
        return self._query_json(prompt)

    def infer_types(self, disassembly: str = "", pseudocode: str = "",
                    metadata: Optional[Dict] = None,
                    gnn_embedding: Optional[List[float]] = None) -> Dict[str, Any]:
        prompt = self._build_prompt(
            task="infer_types",
            instruction='Analyze the code and infer data types for parameters, return values, and local variables. Return JSON with keys: "parameters": list of {"name": str, "type": str}, "return_type": str, "locals": list of {"name": str, "type": str}, "reasoning": str.',
            disassembly=disassembly, pseudocode=pseudocode,
            metadata=metadata, gnn_embedding=gnn_embedding,
        )
        return self._query_json(prompt)

    def summarize_function(self, disassembly: str = "", pseudocode: str = "",
                           metadata: Optional[Dict] = None,
                           gnn_embedding: Optional[List[float]] = None) -> Dict[str, Any]:
        prompt = self._build_prompt(
            task="summarize_function",
            instruction='Provide a comprehensive summary of what this function does. Return JSON with keys: "summary" (string), "behavior" (string), "side_effects" (list of strings), "algorithmic_intent" (string), "complexity_estimate" (string).',
            disassembly=disassembly, pseudocode=pseudocode,
            metadata=metadata, gnn_embedding=gnn_embedding,
        )
        return self._query_json(prompt)

    def explain_basic_block(self, block_disassembly: str = "",
                            block_addr: Optional[int] = None,
                            context: Optional[Dict] = None) -> Dict[str, Any]:
        extra_context = ""
        if block_addr is not None:
            extra_context += f"\n[BLOCK_ADDRESS]: 0x{block_addr:x}"
        if context:
            extra_context += f"\n[CONTEXT]: {json.dumps(context)}"
        prompt = self._build_prompt(
            task="explain_basic_block",
            instruction='Explain what this basic block of assembly does in plain English. Return JSON with keys: "explanation" (string), "purpose" (string), "data_flow" (string describing register/memory changes).',
            disassembly=block_disassembly, extra=extra_context,
        )
        return self._query_json(prompt)

    def explain_cfg_region(self, region_disassembly: str = "",
                           region_edges: Optional[List] = None,
                           metadata: Optional[Dict] = None,
                           gnn_embedding: Optional[List[float]] = None) -> Dict[str, Any]:
        extra = ""
        if region_edges:
            extra += f"\n[CFG_EDGES]: {json.dumps(region_edges)}"
        prompt = self._build_prompt(
            task="explain_cfg_region",
            instruction='Analyze this CFG region (loop, branch, or subgraph) and explain its behavior. Return JSON with keys: "explanation" (string), "pattern" (string - e.g., loop, if-else, switch), "iteration_behavior" (string if loop), "exit_conditions" (list of strings).',
            disassembly=region_disassembly, metadata=metadata,
            gnn_embedding=gnn_embedding, extra=extra,
        )
        return self._query_json(prompt)

    def annotate_code(self, pseudocode: str = "", disassembly: str = "",
                      metadata: Optional[Dict] = None) -> Dict[str, Any]:
        prompt = self._build_prompt(
            task="annotate_code",
            instruction='Add detailed inline comments to the following code. Return JSON with key "annotated_code" (string with comments added).',
            disassembly=disassembly, pseudocode=pseudocode, metadata=metadata,
        )
        return self._query_json(prompt)

    def detect_vulnerabilities(self, disassembly: str = "", pseudocode: str = "",
                               metadata: Optional[Dict] = None) -> Dict[str, Any]:
        prompt = self._build_prompt(
            task="detect_vulnerabilities",
            instruction='Analyze this code for security vulnerabilities. Return JSON with key "vulnerabilities": list of {"type": str, "severity": str, "description": str, "location": str, "recommendation": str}.',
            disassembly=disassembly, pseudocode=pseudocode, metadata=metadata,
        )
        return self._query_json(prompt)

    # ── Tool-calling support ───────────────────────────────────────────────

    @classmethod
    def register_tool(cls, name: str, handler, description: str = ""):
        cls.TOOL_REGISTRY[name] = {"handler": handler, "description": description}

    def resolve_tool_call(self, tool_name: str, arguments: Dict) -> Any:
        tool = self.TOOL_REGISTRY.get(tool_name)
        if tool is None:
            return {"error": f"Unknown tool: {tool_name}"}
        try:
            return tool["handler"](**arguments)
        except Exception as e:
            return {"error": str(e)}

    # ── Enhanced prompt construction (Step 6) ──────────────────────────────

    def _build_prompt(self, task: str, instruction: str, disassembly: str = "",
                      pseudocode: str = "", metadata: Optional[Dict] = None,
                      gnn_embedding: Optional[List[float]] = None,
                      extra: str = "", context_functions: Optional[List[str]] = None,
                      call_chains: Optional[List[str]] = None,
                      data_flow: Optional[str] = None) -> str:
        parts = [
            "You are an expert reverse engineer and binary analyst.",
            f"Task: {task}", "", instruction, "",
        ]
        if gnn_embedding:
            trunc = gnn_embedding[:32]
            parts.append(
                f"[CFG_EMBEDDING]: {json.dumps(trunc)} "
                f"(dim={len(gnn_embedding)}, showing first 32)"
            )
            parts.append("Use the CFG embedding to understand structural patterns.")
            parts.append("")
        if disassembly:
            parts.append(f"[DISASSEMBLY]:\n{disassembly}\n")
        if pseudocode:
            parts.append(f"[PSEUDOCODE]:\n{pseudocode}\n")
        if context_functions:
            parts.append(f"[CONTEXT_FUNCTIONS]:\n" + "\n".join(context_functions) + "\n")
        if call_chains:
            parts.append(f"[CALL_CHAINS]:\n" + "\n".join(call_chains) + "\n")
        if data_flow:
            parts.append(f"[DATAFLOW_SUMMARY]:\n{data_flow}\n")
        if metadata:
            dataflow = metadata.pop("dataflow_summary", None)
            if dataflow:
                parts.append(f"[DATAFLOW_SUMMARY]:\n{dataflow}\n")
            parts.append(f"[METADATA]: {json.dumps(metadata, default=str)}\n")
        if extra:
            parts.append(extra + "\n")
        parts.append("Respond ONLY with valid JSON. Do not include markdown fences or explanations outside the JSON.")
        return "\n".join(parts)

    # ── LLM query ──────────────────────────────────────────────────────────

    def _query(self, prompt: str) -> str:
        if self.client is None:
            return json.dumps({"error": f"No LLM client available for provider '{self.provider}'."})
        try:
            if self.provider == "openai":
                return self._query_openai(prompt)
            elif self.provider == "anthropic":
                return self._query_anthropic(prompt)
            elif self.provider in ("mistral", "local"):
                return self._query_openai_compat(prompt)
            else:
                return json.dumps({"error": f"Unsupported provider: {self.provider}"})
        except Exception as e:
            return json.dumps({"error": f"LLM query failed: {str(e)}"})

    def _query_json(self, prompt: str) -> Dict[str, Any]:
        raw = self._query(prompt)
        try:
            text = raw.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                text = "\n".join(lines)
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw_response": raw, "error": "Failed to parse JSON from LLM response"}

    def _query_openai(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert binary analyst. Always respond with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=self.temperature, max_tokens=self.max_tokens,
        )
        return response.choices[0].message.content or ""

    def _query_anthropic(self, prompt: str) -> str:
        response = self.client.messages.create(
            model=self.model, max_tokens=self.max_tokens,
            temperature=self.temperature,
            system="You are an expert binary analyst. Always respond with valid JSON.",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text if response.content else ""

    def _query_openai_compat(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert binary analyst. Always respond with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=self.temperature, max_tokens=self.max_tokens,
        )
        return response.choices[0].message.content or ""

    def _init_client(self):
        if self.provider == "openai":
            if not _OPENAI_AVAILABLE:
                print("[LLMAgent] openai package not installed.")
                return None
            if not self.api_key:
                print("[LLMAgent] No OpenAI API key found. Set OPENAI_API_KEY env var.")
                return None
            return openai.OpenAI(api_key=self.api_key, base_url=self.api_base)
        elif self.provider == "anthropic":
            if not _ANTHROPIC_AVAILABLE:
                print("[LLMAgent] anthropic package not installed.")
                return None
            if not self.api_key:
                print("[LLMAgent] No Anthropic API key found. Set ANTHROPIC_API_KEY env var.")
                return None
            return anthropic.Anthropic(api_key=self.api_key)
        elif self.provider in ("mistral", "local"):
            if not _OPENAI_AVAILABLE:
                print("[LLMAgent] openai package needed for OpenAI-compatible APIs.")
                return None
            base = self.api_base or self._default_api_base()
            return openai.OpenAI(
                api_key=self.api_key or "not-needed",
                base_url=base,
                timeout=60.0,
            )
        else:
            print(f"[LLMAgent] Unknown provider: {self.provider}")
            return None

    def _default_model(self) -> str:
        defaults = {
            "openai": "gpt-4o", "anthropic": "claude-sonnet-4-20250514",
            "mistral": "mistral-large-latest", "local": "default",
        }
        return defaults.get(self.provider, "gpt-4o")

    def _resolve_api_key(self) -> Optional[str]:
        env_keys = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "mistral": "MISTRAL_API_KEY"}
        env_var = env_keys.get(self.provider)
        return os.environ.get(env_var) if env_var else None

    def _default_api_base(self) -> str:
        bases = {"mistral": "https://api.mistral.ai/v1", "local": "http://localhost:11434/v1"}
        return bases.get(self.provider, "http://localhost:8000/v1")
