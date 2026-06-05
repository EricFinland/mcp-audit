"""Core types shared by every detector.

Everything a detector produces is a `Finding`. One schema -> trivial JSON / markdown /
CI output. Detectors are deterministic and run with no network by default.
"""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # nice CLI label
        return self.name


class Confidence(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    def __str__(self) -> str:
        return self.value


@dataclass
class ToolInfo:
    """A single tool as declared by an MCP server."""
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    """Everything a detector might look at.

    `tools` comes from live introspection (connect.py). `source_files` and `config_files`
    come from the pre-install source pass (sources.py). All are optional so detectors can
    run on whatever is available.
    """
    server_label: str
    tools: list[ToolInfo] = field(default_factory=list)
    source_files: list[Path] = field(default_factory=list)
    config_files: list[Path] = field(default_factory=list)
    root: Path | None = None


@dataclass
class Finding:
    id: str                       # stable detector id, e.g. "MCP-AUDIT-D1-EXFIL"
    title: str
    severity: Severity
    owasp_id: str                 # e.g. "MCP03"
    confidence: Confidence
    location: str                 # tool name, file:line, etc.
    evidence: str                 # the offending snippet (truncated)
    recommendation: str

    def fingerprint(self) -> str:
        """Stable short id for this finding, used to whitelist false positives.

        Built from the detector id + OWASP id + location + evidence so the same finding on
        the same target hashes identically across runs, but a different finding does not.
        """
        key = f"{self.id}|{self.owasp_id}|{self.location}|{self.evidence}".encode("utf-8")
        return hashlib.sha256(key).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = str(self.severity)
        d["confidence"] = str(self.confidence)
        d["fingerprint"] = self.fingerprint()
        return d


class Detector:
    """Base class. Subclasses implement `scan`."""
    name: str = "detector"
    owasp_id: str = "MCP00"

    def scan(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError


def truncate(text: str, limit: int = 160) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"
