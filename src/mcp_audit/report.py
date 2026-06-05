"""Render findings as a rich terminal table, JSON, or a markdown report."""
from __future__ import annotations

import json
from collections import Counter

from .detectors.base import Finding, Severity
from .owasp import OWASP_MCP, label

_SEV_COLOR = {
    "CRITICAL": "bold white on red", "HIGH": "bold red",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}


def to_json(findings: list[Finding], server: str, suppressed: int = 0) -> str:
    return json.dumps(
        {"server": server, "count": len(findings), "suppressed": suppressed,
         "findings": [f.to_dict() for f in findings]},
        indent=2,
    )


def print_table(findings: list[Finding], server: str, suppressed: int = 0) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:  # graceful fallback
        _plain(findings, server)
        return

    console = Console()
    console.rule(f"[bold]mcp-audit[/bold]  {server}")
    if not findings:
        console.print("[bold green]No findings.[/bold green] "
                      "(Note: a clean static scan does not prove a server is safe; see report.)")
        if suppressed:
            console.print(f"[dim]{suppressed} finding(s) suppressed by allowlist.[/dim]")
        return

    table = Table(show_lines=False, expand=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("OWASP", no_wrap=True)
    table.add_column("Finding")
    table.add_column("Location", overflow="fold")
    table.add_column("Conf", no_wrap=True)
    for f in sorted(findings, key=lambda x: x.severity, reverse=True):
        style = _SEV_COLOR.get(str(f.severity), "")
        table.add_row(f"[{style}]{f.severity}[/{style}]", f.owasp_id, f.title,
                      f.location, str(f.confidence))
    console.print(table)

    counts = Counter(str(f.severity) for f in findings)
    summary = "  ".join(f"{k}: {counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[k])
    console.print(f"\n[bold]{len(findings)} findings[/bold]   {summary}")
    if suppressed:
        console.print(f"[dim]{suppressed} finding(s) suppressed by allowlist.[/dim]")
    console.print("[dim]Suppress a false positive: mcp-audit allow <fingerprint>  "
                  "(fingerprints in --json / --report).[/dim]")


def _plain(findings: list[Finding], server: str) -> None:
    print(f"== mcp-audit: {server} ==")
    for f in sorted(findings, key=lambda x: x.severity, reverse=True):
        print(f"[{f.severity}] {f.owasp_id} {f.title} @ {f.location} (conf={f.confidence})")
    print(f"{len(findings)} findings")


def to_markdown(findings: list[Finding], server: str, suppressed: int = 0) -> str:
    lines = [f"# mcp-audit report: `{server}`", ""]
    counts = Counter(str(f.severity) for f in findings)
    lines.append(f"**{len(findings)} findings** ("
                 + ", ".join(f"{k}: {counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[k])
                 + ")")
    if suppressed:
        lines.append("")
        lines.append(f"_{suppressed} finding(s) suppressed by allowlist._")
    lines.append("")

    if findings:
        lines += ["## Findings", "", "| Severity | OWASP | Finding | Location | Confidence |",
                  "|---|---|---|---|---|"]
        for f in sorted(findings, key=lambda x: x.severity, reverse=True):
            lines.append(f"| {f.severity} | {f.owasp_id} | {f.title} | `{f.location}` | {f.confidence} |")
        lines.append("")
        lines += ["### Detail", ""]
        for f in sorted(findings, key=lambda x: x.severity, reverse=True):
            lines += [f"#### {f.severity} · {label(f.owasp_id)} · {f.title}",
                      f"- **Where:** `{f.location}`",
                      f"- **Evidence:** `{f.evidence}`",
                      f"- **Fix:** {f.recommendation}",
                      f"- **Fingerprint:** `{f.fingerprint()}` "
                      f"(false positive? `mcp-audit allow {f.fingerprint()}`)", ""]

    # The honesty section: what a static scan can and cannot prove.
    lines += ["## Coverage & limitations", "",
              "mcp-audit is a *pre-install static* scanner. Coverage against the OWASP MCP Top 10:", "",
              "| OWASP | Risk | Coverage |", "|---|---|---|"]
    cov_label = {"full": "✅ full", "partial": "🟡 partial", "out_of_scope": "❌ out of scope"}
    for oid, meta in OWASP_MCP.items():
        lines.append(f"| {oid} | {meta['title']} | {cov_label[meta['coverage']]} |")
    lines += ["",
              "A clean scan **does not** prove a server is safe. Static analysis cannot catch "
              "rug-pulls (use `baseline`/`diff`), runtime auth failures (MCP07), scope creep "
              "(MCP02), or telemetry gaps (MCP08). Pair with a runtime proxy and identity gateway "
              "for defense in depth.", ""]
    return "\n".join(lines)
