"""D1 - Tool Poisoning detector (OWASP MCP03).

Static analysis of declared tool descriptions and parameter schemas. Tool descriptions
are read by the model as authoritative, so hidden instructions here are the #1 MCP attack.

The regex layer is driven by a loadable pattern pack (`rules/poisoning.yaml`) so rules can be
extended without a release; the in-code defaults below are the fallback and the merge base.
Structural checks (zero-width unicode, HTML/markdown comment smuggling) stay in code. The
optional LLM second-opinion pass lives elsewhere and is off by default.
"""
from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from .base import Confidence, Detector, Finding, ScanContext, Severity, ToolInfo, truncate

_SEV = {"INFO": Severity.INFO, "LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}
_CONF = {"low": Confidence.LOW, "medium": Confidence.MEDIUM, "high": Confidence.HIGH}


@dataclass(frozen=True)
class _Rule:
    id: str
    pattern: re.Pattern[str]
    severity: Severity
    owasp_id: str
    confidence: Confidence
    title: str
    recommendation: str


# In-code defaults: used directly if the YAML pack is missing/unreadable, and the merge base
# the pack overrides by id.
_BUILTIN_RULES: list[_Rule] = [
    _Rule(
        "D1-EXFIL",
        re.compile(r"\b(send|post|upload|exfiltrat|forward|transmit|leak|report)\b[^.]{0,60}"
                   r"(https?://|\bwebhook\b|\bendpoint\b|to (the )?(server|url|address))", re.IGNORECASE),
        Severity.CRITICAL, "MCP03", Confidence.HIGH,
        "Tool description instructs data exfiltration",
        "Description tells the agent to send data to an external destination. Treat the server "
        "as malicious until proven otherwise.",
    ),
    _Rule(
        "D1-SENSITIVE-READ",
        re.compile(r"(~/?\.ssh|id_rsa|id_ed25519|\.env\b|\.aws/credentials|\.config/|"
                   r"/etc/passwd|\.netrc|secrets?\.(json|ya?ml|txt))", re.IGNORECASE),
        Severity.HIGH, "MCP03", Confidence.HIGH,
        "Tool description references sensitive files",
        "Description references credentials/keys/secret paths a benign tool should not need. "
        "Verify the tool's actual behavior.",
    ),
    _Rule(
        "D1-DIRECTIVE",
        re.compile(r"\b(ignore (all |the )?previous|disregard (the |all )?(above|prior)|"
                   r"do not (tell|inform|mention|reveal)|don't (tell|mention)|"
                   r"before (doing anything|you (do|respond|answer))|"
                   r"you must|always (call|run|read|send)|without (telling|informing) the user)\b",
                   re.IGNORECASE),
        Severity.MEDIUM, "MCP03", Confidence.MEDIUM,
        "Model-directed imperative in tool description",
        "Description gives the model commands ('ignore previous', 'do not tell the user', etc.) "
        "rather than describing the tool. Review intent.",
    ),
]


def _pack_path() -> Path | None:
    """Locate a pattern pack: env override, then cwd, then the packaged default."""
    candidates: list[Path] = []
    env = os.environ.get("MCP_AUDIT_RULES")
    if env:
        candidates.append(Path(env))
    candidates.append(Path.cwd() / "rules" / "poisoning.yaml")
    candidates.append(Path(__file__).resolve().parent.parent / "rules" / "poisoning.yaml")
    for c in candidates:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return None


def load_rules() -> list[_Rule]:
    """Built-in defaults merged with the YAML pack (pack overrides/extends by id)."""
    rules: dict[str, _Rule] = {r.id: r for r in _BUILTIN_RULES}
    path = _pack_path()
    if path is None:
        return list(rules.values())
    try:
        import yaml  # pyyaml is a declared dependency; degrade if somehow absent
        data = yaml.safe_load(path.read_text("utf-8", "ignore")) or {}
    except Exception:
        return list(rules.values())
    for raw in data.get("rules", []) or []:
        try:
            rid = str(raw["id"])
            base = rules.get(rid)
            pat = re.compile(raw["pattern"], re.IGNORECASE) if raw.get("pattern") \
                else (base.pattern if base else None)
            if pat is None:
                continue
            rules[rid] = _Rule(
                id=rid,
                pattern=pat,
                severity=_SEV.get(str(raw.get("severity", "")).upper(),
                                  base.severity if base else Severity.MEDIUM),
                owasp_id=str(raw.get("owasp_id", base.owasp_id if base else "MCP03")),
                confidence=_CONF.get(str(raw.get("confidence", "")).lower(),
                                     base.confidence if base else Confidence.MEDIUM),
                title=str(raw.get("title") or (base.title if base else raw.get("description"))
                          or "Suspicious tool-description pattern"),
                recommendation=str(raw.get("recommendation")
                                   or (base.recommendation if base else raw.get("description"))
                                   or "Review this tool description against the server's stated purpose."),
            )
        except (KeyError, re.error):
            continue
    return list(rules.values())


_RULES = load_rules()
_RULES_BY_ID = {r.id: r for r in _RULES}

# HTML / markdown comment smuggling (structural; stays in code).
_COMMENT_SMUGGLE = re.compile(r"<!--.*?-->", re.DOTALL)


def _has_hidden_unicode(text: str) -> str | None:
    """Return the first zero-width / bidi control char found, if any."""
    for ch in text:
        if ch in "\u200b\u200c\u200d\u2060\ufeff\u202a\u202b\u202c\u202d\u202e":
            return f"U+{ord(ch):04X} ({unicodedata.name(ch, 'control')})"
    return None


class ToolPoisoningDetector(Detector):
    name = "tool_poisoning"
    owasp_id = "MCP03"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            findings.extend(self._scan_tool(ctx.server_label, tool))
        return findings

    def _scan_tool(self, server: str, tool: ToolInfo) -> list[Finding]:
        out: list[Finding] = []
        # Gather all text the model would see: description + every param description.
        blobs: list[tuple[str, str]] = [("description", tool.description or "")]
        for pname, pschema in (tool.input_schema.get("properties", {}) or {}).items():
            if isinstance(pschema, dict) and pschema.get("description"):
                blobs.append((f"param:{pname}", str(pschema["description"])))

        for where, text in blobs:
            if not text:
                continue
            loc = f"{server} :: tool '{tool.name}' ({where})"

            hidden = _has_hidden_unicode(text)
            if hidden:
                out.append(self._f(
                    "D1-HIDDEN-UNICODE", "Hidden/zero-width characters in tool text",
                    Severity.HIGH, Confidence.HIGH, loc, hidden,
                    "Tool text contains invisible characters often used to smuggle "
                    "instructions past human review. Inspect the raw bytes; reject if unexplained.",
                ))

            for rule in _RULES:
                if rule.pattern.search(text):
                    out.append(self._f(rule.id, rule.title, rule.severity, rule.confidence,
                                       loc, text, rule.recommendation))

            for m in _COMMENT_SMUGGLE.finditer(text):
                inner = m.group(0)
                directive = _RULES_BY_ID.get("D1-DIRECTIVE")
                sensitive = _RULES_BY_ID.get("D1-SENSITIVE-READ")
                if (directive and directive.pattern.search(inner)) or \
                   (sensitive and sensitive.pattern.search(inner)):
                    out.append(self._f(
                        "D1-COMMENT-SMUGGLE", "Instructions hidden in HTML/markdown comment",
                        Severity.HIGH, Confidence.HIGH, loc, inner,
                        "Hidden comment carries model-directed instructions. Classic tool "
                        "poisoning vector.",
                    ))
        return out

    def _f(self, sid, title, sev, conf, loc, evidence, rec) -> Finding:
        return Finding(
            id=f"MCP-AUDIT-{sid}", title=title, severity=sev, owasp_id=self.owasp_id,
            confidence=conf, location=loc, evidence=truncate(evidence), recommendation=rec,
        )
