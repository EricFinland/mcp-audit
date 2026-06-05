"""D6 - Intent-flow subversion / prompt-injection corpus (OWASP MCP06).

Matches a loadable corpus of prompt-injection signatures (system-prompt overrides, role
hijacks, prompt-leak attempts, role-delimiter injection) against the agent-facing text channel:
tool and parameter descriptions, plus config files. This is the corpus-matching lens; the D1
tool-poisoning detector is the structural lens. The two are independent and can both fire.

Partial MCP06 coverage by design: a static scanner sees declared text, not live tool responses.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .base import Confidence, Detector, Finding, ScanContext, Severity, truncate

_SEV = {"INFO": Severity.INFO, "LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}
_CONF = {"low": Confidence.LOW, "medium": Confidence.MEDIUM, "high": Confidence.HIGH}


@dataclass(frozen=True)
class _Sig:
    id: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    title: str
    recommendation: str


_BUILTIN: list[_Sig] = [
    _Sig("INJ-SYSTEM-OVERRIDE",
         re.compile(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}"
                    r"\b(system prompt|system message|previous instructions|prior instructions|"
                    r"your instructions|guidelines|safety rules|restrictions)\b", re.IGNORECASE),
         Severity.HIGH, Confidence.MEDIUM,
         "Attempt to override the system prompt or instructions",
         "Text instructs the model to discard its governing instructions, the core of an "
         "intent-flow attack. A tool description should describe a tool, not reprogram the agent."),
    _Sig("INJ-ROLE-HIJACK",
         re.compile(r"\b(you are (now )?|act as|pretend (that )?you are|enable)[^.\n]{0,40}"
                    r"(dan\b|developer mode|jailbroken|unrestricted|no (restrictions|rules|guidelines)|"
                    r"without (any )?(restrictions|filter|guardrails))", re.IGNORECASE),
         Severity.HIGH, Confidence.MEDIUM,
         "Role hijack or jailbreak persona",
         "Text tries to switch the model into an unrestricted persona. Treat the server as hostile."),
    _Sig("INJ-PROMPT-LEAK",
         re.compile(r"\b(reveal|repeat|print|show|output|disclose|tell me)\b[^.\n]{0,40}"
                    r"\b(system prompt|initial instructions|your instructions|"
                    r"the (above|prior) prompt|everything above)\b", re.IGNORECASE),
         Severity.MEDIUM, Confidence.MEDIUM,
         "Attempt to leak the system prompt",
         "Text tries to exfiltrate the hidden system prompt. A benign tool has no reason to ask for it."),
    _Sig("INJ-DELIMITER",
         re.compile(r"</?(system|assistant|user|instructions?)\s*>|\[/?INST\]|"
                    r"<\|im_(start|end)\|>|###\s*(system|instruction)", re.IGNORECASE),
         Severity.MEDIUM, Confidence.MEDIUM,
         "Prompt-delimiter or role-marker injection",
         "Text embeds chat/role delimiters to forge a new turn or system message. Strip and reject."),
    _Sig("INJ-NEW-INSTRUCTIONS",
         re.compile(r"\b((new|updated|real|actual|secret) instructions?\s*:|"
                    r"from now on,? you (will|must|should|are))", re.IGNORECASE),
         Severity.MEDIUM, Confidence.MEDIUM,
         "Injected replacement instructions",
         "Text asserts a new set of instructions for the model to follow. Review intent; do not obey."),
]


def _pack_path() -> Path | None:
    candidates: list[Path] = []
    env = os.environ.get("MCP_AUDIT_INJECTION")
    if env:
        candidates.append(Path(env))
    candidates.append(Path.cwd() / "rules" / "injection_corpus.yaml")
    candidates.append(Path(__file__).resolve().parent.parent / "rules" / "injection_corpus.yaml")
    for c in candidates:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return None


def load_corpus() -> list[_Sig]:
    """Built-in signatures merged with the YAML corpus (pack overrides/extends by id)."""
    sigs: dict[str, _Sig] = {s.id: s for s in _BUILTIN}
    path = _pack_path()
    if path is None:
        return list(sigs.values())
    try:
        import yaml
        data = yaml.safe_load(path.read_text("utf-8", "ignore")) or {}
    except Exception:
        return list(sigs.values())
    for raw in data.get("rules", []) or []:
        try:
            rid = str(raw["id"])
            base = sigs.get(rid)
            pat = re.compile(raw["pattern"], re.IGNORECASE) if raw.get("pattern") \
                else (base.pattern if base else None)
            if pat is None:
                continue
            sigs[rid] = _Sig(
                id=rid, pattern=pat,
                severity=_SEV.get(str(raw.get("severity", "")).upper(),
                                  base.severity if base else Severity.MEDIUM),
                confidence=_CONF.get(str(raw.get("confidence", "")).lower(),
                                     base.confidence if base else Confidence.MEDIUM),
                title=str(raw.get("title") or (base.title if base else None)
                          or "Prompt-injection signature matched"),
                recommendation=str(raw.get("recommendation")
                                   or (base.recommendation if base else None)
                                   or "Review this text for intent-flow subversion."),
            )
        except (KeyError, re.error):
            continue
    return list(sigs.values())


_SIGS = load_corpus()


class IntentFlowDetector(Detector):
    name = "intent_flow"
    owasp_id = "MCP06"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for tool in ctx.tools:
            texts: list[tuple[str, str]] = [("description", tool.description or "")]
            for pname, pschema in (tool.input_schema.get("properties", {}) or {}).items():
                if isinstance(pschema, dict) and pschema.get("description"):
                    texts.append((f"param:{pname}", str(pschema["description"])))
            for where, text in texts:
                out.extend(self._match(text, f"{ctx.server_label} :: tool '{tool.name}' ({where})"))
        for path in ctx.config_files:
            try:
                text = path.read_text("utf-8", "ignore")
            except OSError:
                continue
            out.extend(self._match(text, str(path)))
        return out

    def _match(self, text: str, loc: str) -> list[Finding]:
        out: list[Finding] = []
        if not text:
            return out
        for sig in _SIGS:
            m = sig.pattern.search(text)
            if m:
                out.append(Finding(
                    id=f"MCP-AUDIT-{sig.id}", title=sig.title, severity=sig.severity,
                    owasp_id=self.owasp_id, confidence=sig.confidence, location=loc,
                    evidence=truncate(m.group(0)), recommendation=sig.recommendation,
                ))
        return out
