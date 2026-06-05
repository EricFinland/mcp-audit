"""D1 - Tool Poisoning detector (OWASP MCP03).

Static analysis of declared tool descriptions and parameter schemas. Tool descriptions
are read by the model as authoritative, so hidden instructions here are the #1 MCP attack.

Deterministic pattern matching only. The optional LLM second-opinion pass lives elsewhere
and is off by default.
"""
from __future__ import annotations

import re
import unicodedata

from .base import Confidence, Detector, Finding, ScanContext, Severity, ToolInfo

# Imperative instructions aimed at the *model* rather than describing the tool.
_DIRECTIVE = re.compile(
    r"\b(ignore (all |the )?previous|disregard (the |all )?(above|prior)|"
    r"do not (tell|inform|mention|reveal)|don't (tell|mention)|"
    r"before (doing anything|you (do|respond|answer))|"
    r"you must|always (call|run|read|send)|without (telling|informing) the user)\b",
    re.IGNORECASE,
)

# Instructions to touch sensitive locations.
_SENSITIVE_PATH = re.compile(
    r"(~/?\.ssh|id_rsa|id_ed25519|\.env\b|\.aws/credentials|"
    r"\.config/|/etc/passwd|\.netrc|secrets?\.(json|ya?ml|txt))",
    re.IGNORECASE,
)

# Exfiltration: an action verb near a URL.
_EXFIL = re.compile(
    r"\b(send|post|upload|exfiltrat|forward|transmit|leak|report)\b[^.]{0,60}"
    r"(https?://|\bwebhook\b|\bendpoint\b|to (the )?(server|url|address))",
    re.IGNORECASE,
)

# HTML / markdown comment smuggling.
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

            if _EXFIL.search(text):
                out.append(self._f(
                    "D1-EXFIL", "Tool description instructs data exfiltration",
                    Severity.CRITICAL, Confidence.HIGH, loc, text,
                    "Description tells the agent to send data to an external destination. "
                    "Treat the server as malicious until proven otherwise.",
                ))

            if _SENSITIVE_PATH.search(text):
                out.append(self._f(
                    "D1-SENSITIVE-READ", "Tool description references sensitive files",
                    Severity.HIGH, Confidence.HIGH, loc, text,
                    "Description references credentials/keys/secret paths a benign tool "
                    "should not need. Verify the tool's actual behavior.",
                ))

            for m in _COMMENT_SMUGGLE.finditer(text):
                inner = m.group(0)
                if _DIRECTIVE.search(inner) or _SENSITIVE_PATH.search(inner):
                    out.append(self._f(
                        "D1-COMMENT-SMUGGLE", "Instructions hidden in HTML/markdown comment",
                        Severity.HIGH, Confidence.HIGH, loc, inner,
                        "Hidden comment carries model-directed instructions. Classic tool "
                        "poisoning vector.",
                    ))

            if _DIRECTIVE.search(text):
                out.append(self._f(
                    "D1-DIRECTIVE", "Model-directed imperative in tool description",
                    Severity.MEDIUM, Confidence.MEDIUM, loc, text,
                    "Description gives the model commands ('ignore previous', 'do not tell "
                    "the user', etc.) rather than describing the tool. Review intent.",
                ))
        return out

    def _f(self, sid, title, sev, conf, loc, evidence, rec) -> Finding:
        from .base import truncate
        return Finding(
            id=f"MCP-AUDIT-{sid}", title=title, severity=sev, owasp_id=self.owasp_id,
            confidence=conf, location=loc, evidence=truncate(evidence), recommendation=rec,
        )
