"""D7 - Context injection & over-sharing heuristic (OWASP MCP10).

Flags tools whose declared surface implies they return more context than a scoped task needs:
unbounded/recursive reads, "all files / every record" language, `SELECT *`, or bulk return of
secrets and environment. Static and heuristic by design (partial MCP10 coverage): we read the
declared description/schema, not runtime responses, so confidence is deliberately low/medium and
the HIGH bar is reserved for explicit bulk-secret exposure.
"""
from __future__ import annotations

import re

from .base import Confidence, Detector, Finding, ScanContext, Severity, truncate

# Bulk return of secrets/credentials/env: the one case worth a HIGH.
_SENSITIVE_BULK = re.compile(
    r"\b(all|every|each|the)\b[^.\n]{0,20}\b(secret|secrets|credential|credentials|"
    r"environment variable|environment variables|env var|env vars|api key|api keys|token|tokens|"
    r"password|passwords)\b", re.IGNORECASE)
# Broad reads over collections.
_BROAD_READ = re.compile(
    r"\b(read|return|fetch|retrieve|dump|export|list|send|expose|collect)\b[^.\n]{0,30}"
    r"\b(all|every|entire|whole|any)\b[^.\n]{0,20}"
    r"\b(file|files|record|records|row|rows|field|fields|column|columns|document|documents|"
    r"message|messages|email|emails|user|users|conversation|conversations|chat history)\b",
    re.IGNORECASE)
# Explicitly unbounded scope.
_UNBOUNDED = re.compile(
    r"\b(no limit|without (a )?limit|unbounded|unlimited|recursively|entire (file ?system|disk|"
    r"home directory|repository)|arbitrary (file|path|location)|any (file|path) (on|in))\b",
    re.IGNORECASE)
# SQL that returns every column.
_SELECT_STAR = re.compile(r"\bselect\s+\*", re.IGNORECASE)


class ContextOversharingDetector(Detector):
    name = "context_oversharing"
    owasp_id = "MCP10"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for tool in ctx.tools:
            blob = tool.description or ""
            for pname, pschema in (tool.input_schema.get("properties", {}) or {}).items():
                if isinstance(pschema, dict) and pschema.get("description"):
                    blob += " " + str(pschema["description"])
            loc = f"{ctx.server_label} :: tool '{tool.name}'"
            out.extend(self._scan_text(blob, loc))
        return out

    def _scan_text(self, text: str, loc: str) -> list[Finding]:
        out: list[Finding] = []
        if not text:
            return out

        m = _SENSITIVE_BULK.search(text)
        if m:
            out.append(self._f(
                "D7-BULK-SECRETS", "Tool appears to return secrets/environment in bulk",
                Severity.HIGH, Confidence.MEDIUM, loc, m.group(0),
                "Returning all secrets or environment to the agent over-shares high-value context. "
                "Scope the tool to the specific value the task needs.",
            ))

        m = _BROAD_READ.search(text)
        if m:
            out.append(self._f(
                "D7-BROAD-READ", "Tool reads/returns an unbounded collection",
                Severity.MEDIUM, Confidence.MEDIUM, loc, m.group(0),
                "A tool that returns 'all files/records/messages' floods the context and widens "
                "the blast radius. Add filters, pagination, or an explicit scope.",
            ))

        m = _UNBOUNDED.search(text)
        if m:
            out.append(self._f(
                "D7-UNBOUNDED-SCOPE", "Tool declares an unbounded or recursive scope",
                Severity.LOW, Confidence.MEDIUM, loc, m.group(0),
                "Unbounded/recursive access reads more than a scoped task needs. Constrain the "
                "path, depth, and result size.",
            ))

        m = _SELECT_STAR.search(text)
        if m:
            out.append(self._f(
                "D7-SELECT-STAR", "Tool returns all columns (SELECT *)",
                Severity.LOW, Confidence.LOW, loc, m.group(0),
                "Selecting every column can leak fields the task does not need. Project only the "
                "columns required.",
            ))
        return out

    def _f(self, sid, title, sev, conf, loc, evidence, rec) -> Finding:
        return Finding(
            id=f"MCP-AUDIT-{sid}", title=title, severity=sev, owasp_id=self.owasp_id,
            confidence=conf, location=loc, evidence=truncate(evidence), recommendation=rec,
        )
