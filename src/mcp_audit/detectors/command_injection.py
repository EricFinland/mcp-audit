"""D3 - Command Injection detector (OWASP MCP05).

Python source gets the full treatment: parsed with the stdlib `ast` module, tracing whether
a shell sink is fed by a dynamically built string (f-string / concatenation / .format / %),
rather than only regex-matching.

JavaScript / TypeScript source (the bulk of the MCP ecosystem) gets a conservative
line-heuristic pass: child_process exec/execSync/spawn-with-shell and eval/new Function,
flagged only when the argument is visibly dynamic and (for bare `exec`) only when the file
imports child_process, so `regex.exec(...)` never fires.

Static taint is intentionally simple (no full dataflow): flag a shell sink whose argument
is not a plain string literal. That catches the realistic MCP server bugs (mcp-remote-style
command injection) with a manageable false-positive rate, surfaced at MEDIUM confidence.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .base import (Confidence, Detector, Finding, ScanContext, Severity, demote,
                   is_build_path, is_test_path, truncate)

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


# --- JavaScript / TypeScript pass (regex heuristics) ---------------------------------
#
# Most MCP servers are TypeScript, so a Python-only detector misses the bulk of the
# ecosystem. We use careful line heuristics rather than a JS parser: only flag shell-sink
# names when the file actually imports child_process (or uses the unambiguous execSync),
# and only when the argument is visibly dynamic (template literal with ${}, string
# concatenation, or a bare identifier). `regex.exec(...)` is excluded by requiring the
# call NOT be preceded by `.` or a word char.

_JS_EXT = {".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"}
_JS_IMPORTS_CP = re.compile(r"""child_process|node:child_process""")
_JS_EXEC_CALL = re.compile(r"(?<![.\w$])(exec|execSync)\s*\(")
_JS_EVAL_CALL = re.compile(r"(?<![.\w$])(eval|new\s+Function)\s*\(")
_JS_SPAWN_SHELL = re.compile(r"(?<![.\w$])(spawn|spawnSync)\s*\(.*shell\s*:\s*true", re.DOTALL)
# Dynamic argument shapes, checked against the text after the call opens.
_JS_TEMPLATE_DYN = re.compile(r"`[^`]*\$\{")
_JS_CONCAT = re.compile(r"""(['"`][^'"`]*['"`]\s*\+|\+\s*['"`])""")
_JS_IDENT_ARG = re.compile(r"^\s*([A-Za-z_$][\w$.]*)\s*[,)]")
# Interpolations wrapped in JSON.stringify are quoted (imperfectly: $() still expands inside
# double quotes on POSIX shells), so treat them as partially mitigated, not clean.
_JS_INTERP = re.compile(r"\$\{\s*([^}]*)\}")


def _all_interp_stringified(tail: str) -> bool:
    groups = _JS_INTERP.findall(tail)
    return bool(groups) and all(g.strip().startswith("JSON.stringify(") for g in groups)


def _scan_js_line(line: str, has_cp_import: bool) -> tuple[str, "Severity"] | None:
    """Return (what, severity) if this line contains a risky JS shell/eval sink."""
    m = _JS_EXEC_CALL.search(line)
    if m:
        name = m.group(1)
        # Bare `exec(` only counts when child_process is imported; `execSync` is unambiguous.
        if name == "execSync" or has_cp_import:
            tail = line[m.end():]
            if _JS_TEMPLATE_DYN.search(tail) or _JS_CONCAT.search(tail):
                if _all_interp_stringified(tail):
                    return (f"{name}() with JSON.stringify-quoted interpolation "
                            "(quoting does not stop $() expansion in POSIX double quotes)",
                            Severity.MEDIUM)
                return (f"{name}() with a dynamically built command", Severity.HIGH)
            if _JS_IDENT_ARG.match(tail):
                return (f"{name}() with a variable command", Severity.MEDIUM)
    m = _JS_EVAL_CALL.search(line)
    if m:
        tail = line[m.end():]
        if _JS_TEMPLATE_DYN.search(tail) or _JS_CONCAT.search(tail) or _JS_IDENT_ARG.match(tail):
            return (f"{m.group(1)}() on a dynamic expression", Severity.HIGH)
    if _JS_SPAWN_SHELL.search(line):
        tail = line[_JS_SPAWN_SHELL.search(line).start():]
        if _JS_TEMPLATE_DYN.search(tail) or _JS_CONCAT.search(tail):
            return ("spawn(..., {shell: true}) with a dynamic command", Severity.HIGH)
    return None


class CommandInjectionDetector(Detector):
    name = "command_injection"
    owasp_id = "MCP05"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in ctx.source_files:
            suffix = path.suffix.lower()
            # A sink in a test harness or build/CI script is real code but not the server's
            # runtime attack surface: demote one severity step rather than going silent.
            dem = is_test_path(path, ctx.root) or is_build_path(path, ctx.root)
            if suffix == ".py":
                try:
                    tree = ast.parse(path.read_text("utf-8", "ignore"), filename=str(path))
                except (OSError, SyntaxError):
                    continue
                v = _Visitor(path)
                v.visit(tree)
                found = v.findings
            elif suffix in _JS_EXT:
                found = self._scan_js(path)
            else:
                continue
            if dem:
                found = [
                    Finding(id=f.id, title=f.title, severity=demote(f.severity),
                            owasp_id=f.owasp_id, confidence=f.confidence, location=f.location,
                            evidence=truncate(f.evidence + " [test/build path]"),
                            recommendation=f.recommendation)
                    for f in found
                ]
            findings.extend(found)
        return findings

    def _scan_js(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text("utf-8", "ignore")
        except OSError:
            return []
        has_cp = bool(_JS_IMPORTS_CP.search(content))
        out: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "*", "/*")):  # skip comments
                continue
            hit = _scan_js_line(line, has_cp)
            if hit:
                what, sev = hit
                out.append(Finding(
                    id="MCP-AUDIT-D3-CMDINJ", title="Possible command injection sink",
                    severity=sev, owasp_id="MCP05",
                    confidence=Confidence.MEDIUM if sev is Severity.HIGH else Confidence.LOW,
                    location=f"{path}:{lineno}", evidence=truncate(what),
                    recommendation="Never build shell commands from untrusted/tool input. Use "
                                   "execFile/spawn with an argv array, avoid shell:true, and "
                                   "validate inputs.",
                ))
        return out
