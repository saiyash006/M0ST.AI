"""
LLM Inference engine for M0ST.

Wraps OpenAI, Anthropic, Mistral, and local LLM backends with
structured prompt construction and JSON response parsing.

This module lives in the AI Engine layer and provides inference
capabilities to agents and security modules.
"""

import json
import os
from typing import Any, Dict, List, Optional

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


class LLMInferenceEngine:
    """
    LLM inference engine with structured prompt construction
    and multi-provider support.
    """

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

    def query(self, prompt: str) -> str:
        """Send prompt to LLM and return raw text response."""
        if self.client is None:
            return json.dumps(
                {"error": f"No LLM client available for provider '{self.provider}'."}
            )
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

    def query_json(self, prompt: str) -> Dict[str, Any]:
        """Send prompt and parse JSON response."""
        raw = self.query(prompt)
        try:
            text = raw.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                text = "\n".join(lines)
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw_response": raw, "error": "Failed to parse JSON from LLM response"}

    def build_prompt(self, task: str, instruction: str, disassembly: str = "",
                     pseudocode: str = "", metadata: Optional[Dict] = None,
                     gnn_embedding: Optional[List[float]] = None,
                     context_functions: Optional[List[str]] = None,
                     call_chains: Optional[List[str]] = None,
                     data_flow: Optional[str] = None,
                     extra: str = "") -> str:
        """Build a structured prompt for the LLM with enhanced context."""
        parts = [
            "You are an expert reverse engineer and binary analyst.",
            f"Task: {task}",
            "",
            instruction,
            "",
        ]

        # Enhanced context (Step 6: LLM Context Construction)
        if context_functions:
            parts.append("[CONTEXT_FUNCTIONS]:")
            for cf in context_functions:
                parts.append(f"  {cf}")
            parts.append("")

        if call_chains:
            parts.append("[CALL_CHAINS]:")
            for chain in call_chains:
                parts.append(f"  {chain}")
            parts.append("")

        if data_flow:
            parts.append(f"[DATA_FLOW]:\n{data_flow}")
            parts.append("")

        if gnn_embedding:
            trunc = gnn_embedding[:32]
            parts.append(
                f"[CFG_EMBEDDING]: {json.dumps(trunc)} "
                f"(dim={len(gnn_embedding)}, showing first 32)"
            )
            parts.append("")

        if disassembly:
            parts.append(f"[DISASSEMBLY]:\n{disassembly}")
            parts.append("")

        if pseudocode:
            parts.append(f"[PSEUDOCODE]:\n{pseudocode}")
            parts.append("")

        if metadata:
            dataflow = metadata.pop("dataflow_summary", None)
            if dataflow and not data_flow:
                parts.append(f"[DATAFLOW_SUMMARY]:\n{dataflow}")
                parts.append("")
            parts.append(f"[METADATA]: {json.dumps(metadata, default=str)}")
            parts.append("")

        if extra:
            parts.append(extra)
            parts.append("")

        parts.append("Respond ONLY with valid JSON. Do not include markdown fences.")
        return "\n".join(parts)

    # ── Provider queries ───────────────────────────────────────────────────

    def _query_openai(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert binary analyst. Always respond with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        return response.choices[0].message.content or ""

    def _query_anthropic(self, prompt: str) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
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
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        return response.choices[0].message.content or ""

    # ── Client initialization ──────────────────────────────────────────────

    def _init_client(self):
        if self.provider == "openai":
            if not _OPENAI_AVAILABLE or not self.api_key:
                return None
            return openai.OpenAI(api_key=self.api_key, base_url=self.api_base)
        elif self.provider == "anthropic":
            if not _ANTHROPIC_AVAILABLE or not self.api_key:
                return None
            return anthropic.Anthropic(api_key=self.api_key)
        elif self.provider in ("mistral", "local"):
            if not _OPENAI_AVAILABLE:
                return None
            base = self.api_base or self._default_api_base()
            return openai.OpenAI(api_key=self.api_key or "not-needed", base_url=base)
        return None

    def _default_model(self) -> str:
        defaults = {"openai": "gpt-4o", "anthropic": "claude-sonnet-4-20250514",
                     "mistral": "mistral-large-latest", "local": "default"}
        return defaults.get(self.provider, "gpt-4o")

    def _resolve_api_key(self) -> Optional[str]:
        env_keys = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY",
                     "mistral": "MISTRAL_API_KEY"}
        env_var = env_keys.get(self.provider)
        return os.environ.get(env_var) if env_var else None

    def _default_api_base(self) -> str:
        bases = {"mistral": "https://api.mistral.ai/v1",
                 "local": "http://localhost:11434/v1"}
        return bases.get(self.provider, "http://localhost:8000/v1")
