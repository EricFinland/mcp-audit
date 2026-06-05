"""D3 - Command Injection detector (OWASP MCP05), AST-based.

This is the detector that justifies choosing Python: it parses server source with the
stdlib `ast` module and traces whether a shell sink is fed by a dynamically built string
(f-string / concatenation / .format / % ), rather than only regex-matching.

Static taint is intentionally simple (no full dataflow): flag a shell sink whose argument
is not a plain string literal. That catches the realistic MCP server bugs (mcp-remote-style
command injection) with a manageable false-positive rate, surfaced at MEDIUM confidence.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .base import Confidence, Detector, Finding, ScanContext, Severity, truncate

_SHELL_CALLS = {
    ("os", "system"), ("os", "popen"),
    ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "Popen"),
    ("subprocess", "check_call"), ("subprocess", "check_output"), ("subprocess", "getoutput"),
}
_EVAL_CALLS = {"eval", "exec"}


def _attr_chain(node: ast.AST) -> tuple[str, str] | None:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return (node.value.id, node.attr)
    return None


def _is_dynamic_string(node: ast.AST) -> bool:
    """True if the expression builds a string from non-literal parts."""
    if isinstance(node, ast.JoinedStr):  # f-string
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call):  # "...".format(...) or " ".join(...)
        chain = node.func.attr if isinstance(node.func, ast.Attribute) else None
        if chain in {"format", "join"}:
            return True
    if isinstance(node, ast.Name):  # a variable - could be tainted; flag low
        return True
    return False


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: Path):
        self.path = path
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        self._check(node)
        self.generic_visit(node)

    def _check(self, node: ast.Call) -> None:
        chain = _attr_chain(node.func)
        is_eval = isinstance(node.func, ast.Name) and node.func.id in _EVAL_CALLS
        shell_true = any(
            isinstance(k, ast.keyword) and k.arg == "shell"
            and isinstance(k.value, ast.Constant) and k.value.value is True
            for k in node.keywords
        )

        if is_eval and node.args and _is_dynamic_string(node.args[0]):
            self._add(node, f"{node.func.id}() on a dynamic expression", Severity.HIGH)
            return

        if chain in _SHELL_CALLS:
            first = node.args[0] if node.args else None
            # shell=True with any dynamic arg is the dangerous case; os.system always is.
            if chain == ("os", "system") and first and _is_dynamic_string(first):
                self._add(node, "os.system() with a dynamically built command", Severity.HIGH)
            elif shell_true and first and _is_dynamic_string(first):
                self._add(node, f"{chain[0]}.{chain[1]}(shell=True) with a dynamic command", Severity.HIGH)
            elif chain == ("os", "popen") and first and _is_dynamic_string(first):
                self._add(node, "os.popen() with a dynamically built command", Severity.MEDIUM)

    def _add(self, node: ast.AST, what: str, sev: Severity) -> None:
        self.findings.append(Finding(
            id="MCP-AUDIT-D3-CMDINJ", title="Possible command injection sink",
            severity=sev, owasp_id="MCP05", confidence=Confidence.MEDIUM,
            location=f"{self.path}:{getattr(node, 'lineno', '?')}",
            evidence=truncate(what),
            recommendation="Never build shell commands from untrusted/tool input. Use a "
                           "parameterized argv list, avoid shell=True, and validate inputs.",
        ))


class CommandInjectionDetector(Detector):
    name = "command_injection"
    owasp_id = "MCP05"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in ctx.source_files:
            if path.suffix.lower() != ".py":
                continue
            try:
                tree = ast.parse(path.read_text("utf-8", "ignore"), filename=str(path))
            except (OSError, SyntaxError):
                continue
            v = _Visitor(path)
            v.visit(tree)
            findings.extend(v.findings)
        return findings
