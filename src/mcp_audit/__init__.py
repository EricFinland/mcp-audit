"""mcp-audit - local-first, pre-install security auditor for MCP servers."""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-audit")
except PackageNotFoundError:  # running from source without an install
    __version__ = "0.1.0"
