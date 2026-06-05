"""Pre-install source pass.

Given a local directory (or a git URL to clone), enumerate source files, config files,
and MCP client configs. This is what lets mcp-audit analyze a server *before* it is wired
into an agent - the "check before you trust" posture.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

_SOURCE_EXT = {".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"}
_CONFIG_NAMES = {"mcp.json", "claude_desktop_config.json", ".env",
                 "package.json", "pyproject.toml", "requirements.txt"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def clone_repo(url: str) -> Path:
    """Shallow-clone a git repo to a temp dir. Read-only analysis afterwards."""
    dest = Path(tempfile.mkdtemp(prefix="mcp-audit-"))
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True, capture_output=True, text=True,
    )
    return dest


def enumerate_sources(root: Path) -> tuple[list[Path], list[Path]]:
    """Return (source_files, config_files) under `root`, skipping noise dirs."""
    sources: list[Path] = []
    configs: list[Path] = []
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.name in _CONFIG_NAMES:
            configs.append(path)
        elif path.suffix.lower() in _SOURCE_EXT:
            sources.append(path)
    return sources, configs


def find_mcp_configs(root: Path) -> list[Path]:
    """MCP09 shadow-server inventory: every MCP client config under the tree."""
    return [p for p in root.rglob("*")
            if p.is_file() and p.name in {"mcp.json", "claude_desktop_config.json"}
            and not any(part in _SKIP_DIRS for part in p.parts)]
