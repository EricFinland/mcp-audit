"""D2 - Hardcoded Secrets detector (OWASP MCP01).

Scans source files, config files, and tool descriptions for credentials. Decodes a few
common encodings before matching so base64/hex-wrapped keys don't slip through.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
from pathlib import Path

from .base import Confidence, Detector, Finding, ScanContext, Severity, truncate

# (label, regex, confidence) - known prefixes are HIGH, generic entropy is MEDIUM.
_PATTERNS: list[tuple[str, re.Pattern[str], Confidence]] = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Confidence.HIGH),
    ("GitHub token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), Confidence.HIGH),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), Confidence.HIGH),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Confidence.HIGH),
    ("Stripe secret key", re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b"), Confidence.HIGH),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Confidence.HIGH),
    ("OpenAI key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), Confidence.MEDIUM),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), Confidence.HIGH),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"), Confidence.HIGH),
    ("Generic secret assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]"
    ), Confidence.MEDIUM),
]

_DECODERS = {
    "base64": lambda s: base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore"),
    "hex": lambda s: binascii.unhexlify(s).decode("utf-8", "ignore"),
}
_B64ISH = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEXISH = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_TEXT_EXT = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".env", ".txt", ".cfg", ".ini"}


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Severity follows confidence so a guessy generic/entropy match is not reported as HIGH.
_CONF_TO_SEV = {Confidence.HIGH: Severity.HIGH, Confidence.MEDIUM: Severity.MEDIUM,
                Confidence.LOW: Severity.LOW}

# Values that are obviously placeholders/examples, not real secrets (e.g. AWS's own
# AKIAIOSFODNN7EXAMPLE, or password='test-password'). High-precision substrings.
_PLACEHOLDER_WORDS = (
    "example", "test", "sample", "placeholder", "changeme", "change-me", "change_me",
    "dummy", "fake", "redacted", "notreal", "not-real", "your-", "your_", "yourkey",
    "insert", "replace", "foobar", "todo", "xxxx", "dummytoken", "mykey", "<", ">", "...",
)

# Path segments where a "secret" is almost always an intentional fixture, so demote it.
_TEST_SEGMENTS = {
    "test", "tests", "__tests__", "testdata", "example", "examples", "sample", "samples",
    "fixture", "fixtures", "mock", "mocks", "docs", "doc", "spec", "specs", "demo", "e2e",
}


def _looks_placeholder(value: str) -> bool:
    lv = value.lower()
    return any(w in lv for w in _PLACEHOLDER_WORDS)


def _is_test_path(path: Path) -> bool:
    parts = [p.lower() for p in path.parts]
    if any(seg in _TEST_SEGMENTS for seg in parts):
        return True
    name = path.name.lower()
    return name.startswith(("test_", "test-")) or name.endswith(("_test.py", ".test.ts", ".spec.ts"))


class SecretsDetector(Detector):
    name = "secrets"
    owasp_id = "MCP01"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # Tool descriptions (a credential pasted into a description is a leak too).
        for tool in ctx.tools:
            findings.extend(self._scan_text(tool.description or "", f"{ctx.server_label} :: tool '{tool.name}'"))

        # Files.
        for path in list(ctx.source_files) + list(ctx.config_files):
            if path.suffix.lower() not in _TEXT_EXT and path.name != ".env":
                continue
            try:
                content = path.read_text("utf-8", "ignore")
            except OSError:
                continue
            findings.extend(self._scan_file(content, path))
        return findings

    def _scan_file(self, content: str, path: Path) -> list[Finding]:
        out: list[Finding] = []
        demote = _is_test_path(path)
        for lineno, line in enumerate(content.splitlines(), 1):
            out.extend(self._scan_text(line, f"{path}:{lineno}", demote=demote))
            # decoded variants
            for blob in _B64ISH.findall(line) + _HEXISH.findall(line):
                for name, dec in _DECODERS.items():
                    try:
                        decoded = dec(blob)
                    except Exception:
                        continue
                    if decoded and decoded.isprintable():
                        sub = self._scan_text(decoded, f"{path}:{lineno} (decoded {name})", demote=demote)
                        out.extend(sub)
        return out

    def _scan_text(self, text: str, loc: str, demote: bool = False) -> list[Finding]:
        out: list[Finding] = []
        for label, pat, conf in _PATTERNS:
            m = pat.search(text)
            if not m:
                continue
            value = m.group(0)
            if label.startswith("Generic"):
                value = value.split("=")[-1].split(":")[-1].strip(" '\"")
                if _shannon(value) < 3.0:  # entropy gate cuts low-information matches
                    continue
            # Skip obvious placeholders/examples (AKIA...EXAMPLE, 'test-password', etc.).
            if _looks_placeholder(value):
                continue
            severity = _CONF_TO_SEV.get(conf, Severity.MEDIUM)
            if demote:  # a credential in a test/example/docs path is almost always a fixture
                severity = Severity(max(Severity.LOW, severity - 1))
            out.append(Finding(
                id="MCP-AUDIT-D2-SECRET", title=f"Possible hardcoded credential ({label})",
                severity=severity, owasp_id=self.owasp_id, confidence=conf,
                location=loc, evidence=truncate(m.group(0)),
                recommendation="Move secrets to environment variables or a secret manager; "
                               "rotate this credential if it is real and was committed.",
            ))
        return out
