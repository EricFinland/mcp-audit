"""D4 - Supply-chain hygiene detector (OWASP MCP04).

Reads dependency manifests (`package.json`, `pyproject.toml`, `requirements.txt`) and the
presence of lockfiles, and reports hygiene problems that make a server a supply-chain risk:

- install/preinstall/postinstall scripts (npm runs these automatically on `npm install`),
  escalated when the script pulls from the network or pipes to a shell
- unpinned dependencies (a server can change under you between installs)
- missing lockfile (no reproducible install)
- dependency names that look like typosquats of popular packages

This is a hygiene score, not a hard block: most findings are LOW/MEDIUM. Install scripts that
fetch-and-exec are the one genuinely dangerous case and are flagged higher.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

try:  # stdlib on 3.11+; degrade quietly if somehow absent
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from .base import Confidence, Detector, Finding, ScanContext, Severity, truncate

# Scripts that run automatically during `npm install`.
_NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall")
# A network-fetch or shell-pipe inside an install script is the dangerous pattern.
_FETCH_EXEC = re.compile(r"\b(curl|wget|iwr|invoke-webrequest)\b|https?://|\|\s*(sh|bash|node|python)\b",
                         re.IGNORECASE)
# Unpinned npm version specifiers.
_NPM_UNPINNED = re.compile(r"^[\^~]|[\*x]|\blatest\b|\s-\s|>=|>|<", re.IGNORECASE)
# Popular packages people typo; conservative list for edit-distance-1 lookalikes.
_POPULAR = {
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "fastapi", "pydantic",
    "express", "react", "lodash", "axios", "chalk", "commander", "typescript", "mcp",
    "modelcontextprotocol", "anthropic", "openai",
}


def _edit_distance_le1(a: str, b: str) -> bool:
    """True if `a` and `b` differ by at most one insert/delete/substitution."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:  # one substitution
        return sum(c1 != c2 for c1, c2 in zip(a, b)) == 1
    # one insert/delete: the shorter must be a subsequence missing exactly one char
    short, long = (a, b) if la < lb else (b, a)
    i = j = edits = 0
    while i < len(short) and j < len(long):
        if short[i] == long[j]:
            i += 1
            j += 1
        else:
            edits += 1
            j += 1
            if edits > 1:
                return False
    return True


_PY_LOCKFILES = {"poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.lock"}
_NPM_LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"}


class SupplyChainDetector(Detector):
    name = "supply_chain"
    owasp_id = "MCP04"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for path in ctx.config_files:
            try:
                if path.name == "package.json":
                    out.extend(self._scan_package_json(path))
                elif path.name == "pyproject.toml":
                    out.extend(self._scan_pyproject(path))
                elif path.name == "requirements.txt":
                    out.extend(self._scan_requirements(path))
            except (OSError, ValueError):
                continue
        return out

    # --- npm -----------------------------------------------------------------
    def _scan_package_json(self, path: Path) -> list[Finding]:
        out: list[Finding] = []
        data = json.loads(path.read_text("utf-8", "ignore"))
        scripts = data.get("scripts", {}) or {}
        for hook in _NPM_INSTALL_HOOKS:
            body = scripts.get(hook)
            if not body:
                continue
            if _FETCH_EXEC.search(str(body)):
                out.append(self._f(
                    "D4-INSTALL-FETCH-EXEC", f"npm '{hook}' script fetches/executes from the network",
                    Severity.HIGH, Confidence.HIGH, f"{path} :: scripts.{hook}", str(body),
                    "An install hook that downloads and runs code executes arbitrary commands the "
                    "moment the package is installed. Treat as malicious until reviewed.",
                ))
            else:
                out.append(self._f(
                    "D4-INSTALL-SCRIPT", f"npm '{hook}' script runs automatically on install",
                    Severity.MEDIUM, Confidence.MEDIUM, f"{path} :: scripts.{hook}", str(body),
                    "Install-time scripts run without the user invoking the tool. Verify the script "
                    "is benign and necessary.",
                ))

        deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(data.get(key, {}) or {})
        for dname, spec in deps.items():
            if isinstance(spec, str) and _NPM_UNPINNED.search(spec):
                out.append(self._f(
                    "D4-UNPINNED", f"Unpinned dependency '{dname}' ({spec})",
                    Severity.LOW, Confidence.MEDIUM, f"{path} :: {dname}", f"{dname}: {spec}",
                    "Pin to an exact version so the dependency cannot change between installs.",
                ))
            out.extend(self._typosquat(dname, path))

        if not self._has_sibling(path, _NPM_LOCKFILES):
            out.append(self._f(
                "D4-NO-LOCKFILE", "No npm lockfile present", Severity.LOW, Confidence.MEDIUM,
                str(path), "package.json without package-lock.json / yarn.lock / pnpm-lock.yaml",
                "Commit a lockfile so installs are reproducible and resolved versions are auditable.",
            ))
        return out

    # --- python --------------------------------------------------------------
    def _scan_pyproject(self, path: Path) -> list[Finding]:
        if tomllib is None:  # pragma: no cover
            return []
        out: list[Finding] = []
        data = tomllib.loads(path.read_text("utf-8", "ignore"))
        deps = (data.get("project", {}) or {}).get("dependencies", []) or []
        for dep in deps:
            name = re.split(r"[\s<>=!~\[]", str(dep), 1)[0].strip()
            if "==" not in str(dep):
                out.append(self._f(
                    "D4-UNPINNED", f"Unpinned dependency '{name}'",
                    Severity.LOW, Confidence.MEDIUM, f"{path} :: {name}", str(dep),
                    "Pin to an exact version (==) so the dependency cannot change between installs.",
                ))
            if name:
                out.extend(self._typosquat(name.lower(), path))
        if not self._has_sibling(path, _PY_LOCKFILES):
            out.append(self._f(
                "D4-NO-LOCKFILE", "No Python lockfile present", Severity.LOW, Confidence.LOW,
                str(path), "pyproject.toml without poetry.lock / uv.lock / pdm.lock",
                "A lockfile makes installs reproducible and the resolved tree auditable.",
            ))
        return out

    def _scan_requirements(self, path: Path) -> list[Finding]:
        out: list[Finding] = []
        for lineno, raw in enumerate(path.read_text("utf-8", "ignore").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if "==" not in line and not line.startswith(("git+", "http")):
                name = re.split(r"[\s<>=!~\[]", line, 1)[0].strip()
                out.append(self._f(
                    "D4-UNPINNED", f"Unpinned dependency '{name}'",
                    Severity.LOW, Confidence.MEDIUM, f"{path}:{lineno}", line,
                    "Pin to an exact version (==) so the dependency cannot change between installs.",
                ))
        return out

    # --- helpers -------------------------------------------------------------
    def _typosquat(self, name: str, path: Path) -> list[Finding]:
        for popular in _POPULAR:
            if _edit_distance_le1(name, popular):
                return [self._f(
                    "D4-TYPOSQUAT", f"Dependency '{name}' looks like a typosquat of '{popular}'",
                    Severity.MEDIUM, Confidence.LOW, f"{path} :: {name}",
                    f"{name} vs {popular}",
                    "A near-miss of a popular package name is a classic supply-chain attack. "
                    "Confirm this is the intended package.",
                )]
        return []

    @staticmethod
    def _has_sibling(path: Path, names: set[str]) -> bool:
        parent = path.parent
        return any((parent / n).exists() for n in names)

    def _f(self, sid, title, sev, conf, loc, evidence, rec) -> Finding:
        return Finding(
            id=f"MCP-AUDIT-{sid}", title=title, severity=sev, owasp_id=self.owasp_id,
            confidence=conf, location=loc, evidence=truncate(evidence), recommendation=rec,
        )
