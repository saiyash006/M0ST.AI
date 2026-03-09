# M0ST — Plugin Development Guide

## Overview

M0ST supports **dynamically loaded analysis plugins**. Plugins are Python files that expose an `analyze()` function. They are automatically discovered and loaded from the `plugins/` directory. When a Program Knowledge Graph (PKG) is attached, plugin results are stored as PKG annotations.

---

## Plugin API

Every plugin must expose a single function:

```python
def analyze(graph_store, func_addr: int) -> dict:
    """
    Analyze a single function and return findings.

    Args:
        graph_store: The graph store instance with full access to
                     functions, basic blocks, instructions, and edges.
        func_addr:   Address of the function to analyze.

    Returns:
        A dict of findings keyed by category name.
        Return an empty dict if no findings.
    """
    findings = []

    # Your analysis logic here...

    return {"my_category": findings} if findings else {}
```

---

## Graph Store API (available in plugins)

| Method                              | Returns       | Description                                     |
| ----------------------------------- | ------------- | ----------------------------------------------- |
| `fetch_functions()`                 | `List[Dict]`  | All functions `{"addr": int, "name": str, ...}` |
| `fetch_basic_blocks(func_addr)`     | `List[int]`   | Block addresses in a function                   |
| `fetch_block_instructions(bb_addr)` | `List[Dict]`  | Instructions `{"addr", "mnemonic", "operands"}` |
| `fetch_flow_edges(func_addr)`       | `List[Tuple]` | CFG edges `[(src, dst), ...]`                   |

---

## Plugin File Structure

```
plugins/
├── __init__.py              # PluginManager (do not modify)
├── anti_debug/
│   └── anti_debug.py        # Anti-debugging detection
├── crypto/
│   └── crypto_detect.py     # Crypto pattern detection
├── entropy/
│   └── entropy_analysis.py  # Shannon entropy analysis
├── magic_pattern/
│   └── magic_detect.py      # File format magic bytes
└── string_decoder/
    └── string_decode.py     # String function detection
```

### Rules

- Plugin files must be `.py` files that do **not** start with `_`
- Plugins can be nested in subdirectories
- `__pycache__` and hidden directories are automatically skipped
- Each plugin module must have a callable `analyze` attribute

---

## Example Plugin: Stack Cookie Detection

Create `plugins/stack_cookie/stack_cookie.py`:

```python
"""
Stack cookie (canary) detection plugin.
Identifies functions that use stack protection mechanisms.
"""

CANARY_PATTERNS = {"__stack_chk_fail", "__stack_chk_guard", "gs:0x14", "fs:0x28"}


def analyze(graph_store, func_addr: int) -> dict:
    blocks = graph_store.fetch_basic_blocks(func_addr)
    findings = []

    for bb in blocks:
        insns = graph_store.fetch_block_instructions(bb)
        for insn in insns:
            mnem = (insn.get("mnemonic") or "").lower()
            ops = insn.get("operands") or []

            # Check for stack canary references
            for op in ops:
                if isinstance(op, str):
                    for pattern in CANARY_PATTERNS:
                        if pattern in op.lower():
                            findings.append({
                                "type": "stack_canary",
                                "addr": insn.get("addr"),
                                "detail": f"Stack cookie reference: {op}",
                            })

            # Check for call to __stack_chk_fail
            if mnem in {"call", "bl"} and ops:
                if "__stack_chk_fail" in ops[0].lower():
                    findings.append({
                        "type": "canary_check",
                        "addr": insn.get("addr"),
                        "detail": "Stack canary validation (call to __stack_chk_fail).",
                    })

    return {"stack_cookie": findings} if findings else {}
```

---

## CLI Usage

```
spider> plugins list
Loaded plugins:
  - anti_debug/anti_debug.py
  - crypto/crypto_detect.py
  - entropy/entropy_analysis.py
  - magic_pattern/magic_detect.py
  - string_decoder/string_decode.py

spider> plugins run 0x401000
Plugin findings for 0x401000:
  crypto: 2 finding(s)
    - Known crypto constant 0x67452301 (MD5/SHA-1 init).
    - Function has high ratio of crypto-style ops (45/120).
```

---

## Tips

- Keep plugins **focused** - one concern per plugin
- Return **empty dicts** when no findings (not `None`)
- Use `try/except` around risky operations
- Plugins run in the main thread - avoid blocking I/O
- Test with `plugins run <addr>` before relying on automatic pipeline execution
