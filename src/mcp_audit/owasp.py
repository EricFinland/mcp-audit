"""OWASP MCP Top 10 (MCP01:2025 - MCP10:2025) metadata and our honest coverage map.

Source: owasp.org/www-project-mcp-top-10 (beta; categories stable, wording may shift).
Coverage reflects what a *pre-install static scanner* can legitimately claim. "full" means
the control type covers the risk on its own; "partial" means meaningful but incomplete;
"out_of_scope" means it needs runtime/identity/telemetry we deliberately don't build.
"""
from __future__ import annotations

OWASP_MCP: dict[str, dict[str, str]] = {
    "MCP01": {"title": "Token Mismanagement & Secret Exposure", "coverage": "partial"},
    "MCP02": {"title": "Privilege Escalation via Scope Creep", "coverage": "out_of_scope"},
    "MCP03": {"title": "Tool Poisoning", "coverage": "full"},
    "MCP04": {"title": "Software Supply Chain Attacks & Dependency Tampering", "coverage": "full"},
    "MCP05": {"title": "Command Injection & Execution", "coverage": "partial"},
    "MCP06": {"title": "Intent Flow Subversion", "coverage": "partial"},
    "MCP07": {"title": "Insufficient Authentication & Authorization", "coverage": "out_of_scope"},
    "MCP08": {"title": "Lack of Audit and Telemetry", "coverage": "out_of_scope"},
    "MCP09": {"title": "Shadow MCP Servers", "coverage": "partial"},
    "MCP10": {"title": "Context Injection & Over-Sharing", "coverage": "partial"},
}


def label(owasp_id: str) -> str:
    entry = OWASP_MCP.get(owasp_id)
    return f"{owasp_id}: {entry['title']}" if entry else owasp_id
