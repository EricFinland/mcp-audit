"""Optional LLM second-opinion pass.

OFF by default. The deterministic detectors are the engine; this is a second opinion that can
add nuance to a flagged snippet. It is local-first: by default it talks to a local model via
Ollama and nothing leaves the machine. `--cloud` switches to a hosted model and prints a loud
warning, because the flagged snippet then leaves the machine. We only ever send the specific
flagged snippet, never whole files, and we degrade silently if no backend is reachable.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable

CLOUD_WARNING = (
    "WARNING: --cloud sends each flagged snippet to a hosted model. Those snippets LEAVE YOUR "
    "MACHINE. Re-run without --cloud to keep everything local (Ollama)."
)

_PROMPT = (
    "You are a security reviewer auditing an MCP server. Below is a single snippet a static "
    "scanner flagged. In ONE short sentence, say whether it looks like a true positive or a "
    "likely false positive, and why. Do not ask for more context.\n\nSNIPPET:\n{snippet}"
)

# A backend is (model, host, prompt) -> str. Injectable so tests never touch a network/daemon.
ChatFn = Callable[[str, "str | None", str], str]


@dataclass
class LLMConfig:
    enabled: bool = False
    cloud: bool = False
    model: str = "llama3"
    host: str | None = None  # Ollama host override, e.g. http://localhost:11434


def _ollama_chat(model: str, host: str | None, prompt: str) -> str:
    import ollama  # optional dependency; ImportError handled by callers
    client = ollama.Client(host=host) if host else ollama
    resp = client.chat(model=model, messages=[{"role": "user", "content": prompt}])
    # ollama returns a dict-like with ["message"]["content"]
    return (resp["message"]["content"] or "").strip()


def second_opinion(snippet: str, cfg: LLMConfig, *, chat: ChatFn | None = None) -> str | None:
    """Return a one-line LLM verdict on `snippet`, or None if the backend is unavailable."""
    snippet = (snippet or "").strip()
    if not snippet:
        return None
    backend = chat or _ollama_chat
    prompt = _PROMPT.format(snippet=snippet[:800])  # cap: only the snippet, bounded
    try:
        out = backend(cfg.model, cfg.host, prompt)
    except Exception:
        return None
    out = " ".join((out or "").split())
    return out[:300] or None


def annotate(findings, cfg: LLMConfig, *, chat: ChatFn | None = None,
             warn: Callable[[str], None] | None = None) -> None:
    """Attach an `llm_note` to each finding in place. No-op unless cfg.enabled."""
    if not cfg.enabled:
        return
    warn = warn or (lambda msg: print(msg, file=sys.stderr))
    if cfg.cloud:
        warn(CLOUD_WARNING)
    for f in findings:
        note = second_opinion(f.evidence, cfg, chat=chat)
        if note:
            f.llm_note = note
