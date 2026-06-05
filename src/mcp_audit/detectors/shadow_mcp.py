"""D5 - Shadow-MCP inventory (OWASP MCP09).

Answers one question for a repo: "what MCP servers would this wire up?" It does not judge
them; it surfaces them so a shadow server (one nobody remembered is configured) cannot hide.

Two signals:
- MCP client configs (`mcp.json`, `claude_desktop_config.json`) that declare servers, listed
  one inventory finding per declared server with its launch command.
- A declared dependency on the MCP SDK (`mcp` / `modelcontextprotocol` / `@modelcontextprotocol/*`),
  which means this repo likely is, or hosts, an MCP server.

Findings are INFO severity: inventory, not vulnerabilities. Confidence is HIGH because these
are facts read straight from the manifest.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from .base import Confidence, Detector, Finding, ScanContext, Severity, truncate

_CLIENT_CONFIGS = {"mcp.json", "claude_desktop_config.json"}
_MCP_DEP_NAMES = {"mcp", "modelcontextprotocol", "fastmcp"}


class ShadowMcpDetector(Detector):
    name = "shadow_mcp"
    owasp_id = "MCP09"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for path in ctx.config_files:
            try:
                if path.name in _CLIENT_CONFIGS:
                    out.extend(self._scan_client_config(path))
                elif path.name == "package.json":
                    out.extend(self._scan_package_deps(path))
                elif path.name == "pyproject.toml":
                    out.extend(self._scan_pyproject(path))
                elif path.name == "requirements.txt":
                    out.extend(self._scan_requirements(path))
            except (OSError, ValueError):
                continue
        return out

    def _scan_client_config(self, path: Path) -> list[Finding]:
        data = json.loads(path.read_text("utf-8", "ignore"))
        # Claude desktop uses "mcpServers"; some mcp.json variants use "servers".
        servers = data.get("mcpServers") or data.get("servers") or {}
        out: list[Finding] = []
        if not isinstance(servers, dict):
            return out
        for name, cfg in servers.items():
            cmd = ""
            if isinstance(cfg, dict):
                parts = [str(cfg.get("command", ""))] + [str(a) for a in cfg.get("args", []) or []]
                cmd = " ".join(p for p in parts if p).strip()
                if not cmd and cfg.get("url"):
                    cmd = str(cfg["url"])
            out.append(self._f(
                f"Declared MCP server '{name}'", path, f"{name}: {cmd or '(no command)'}",
                "This config wires up an MCP server. Confirm it is known and trusted; an "
                "unrecognized entry here is a shadow server.",
            ))
        return out

    def _scan_package_deps(self, path: Path) -> list[Finding]:
        data = json.loads(path.read_text("utf-8", "ignore"))
        deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies"):
            deps.update(data.get(key, {}) or {})
        out: list[Finding] = []
        for dname in deps:
            if dname in _MCP_DEP_NAMES or dname.startswith("@modelcontextprotocol/"):
                out.append(self._dep_finding(dname, path))
        return out

    def _scan_pyproject(self, path: Path) -> list[Finding]:
        if tomllib is None:  # pragma: no cover
            return []
        data = tomllib.loads(path.read_text("utf-8", "ignore"))
        deps = (data.get("project", {}) or {}).get("dependencies", []) or []
        out: list[Finding] = []
        for dep in deps:
            name = re.split(r"[\s<>=!~\[]", str(dep), 1)[0].strip().lower()
            if name in _MCP_DEP_NAMES:
                out.append(self._dep_finding(name, path))
        return out

    def _scan_requirements(self, path: Path) -> list[Finding]:
        out: list[Finding] = []
        for raw in path.read_text("utf-8", "ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "-")):
                continue
            name = re.split(r"[\s<>=!~\[]", line, 1)[0].strip().lower()
            if name in _MCP_DEP_NAMES:
                out.append(self._dep_finding(name, path))
        return out

    def _dep_finding(self, name: str, path: Path) -> Finding:
        return self._f(
            f"Repo depends on the MCP SDK ('{name}')", path, name,
            "This repo declares an MCP dependency, so it likely defines or hosts an MCP server. "
            "Make sure it is in your inventory of trusted servers.",
        )

    def _f(self, title: str, path: Path, evidence: str, rec: str) -> Finding:
        return Finding(
            id="MCP-AUDIT-D5-SHADOW", title=title, severity=Severity.INFO,
            owasp_id=self.owasp_id, confidence=Confidence.HIGH, location=str(path),
            evidence=truncate(evidence), recommendation=rec,
        )
