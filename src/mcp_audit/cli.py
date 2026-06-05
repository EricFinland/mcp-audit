"""mcp-audit CLI.

    mcp-audit scan ./path/to/server      # pre-install: analyze source + tool surface
    mcp-audit scan --stdio "python server.py"
    mcp-audit scan --http http://localhost:8000/mcp
    mcp-audit scan --git https://github.com/owner/repo
    mcp-audit baseline --stdio "python server.py"   # store tool-hash baseline
    mcp-audit diff --stdio "python server.py"        # rug-pull drift check
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import typer

from .detectors import ALL_DETECTORS, Finding, ScanContext, Severity, ToolInfo

app = typer.Typer(add_completion=False, help="Local-first, pre-install security auditor for MCP servers.")

_BASELINE_DIR = Path.home() / ".mcp-audit" / "baselines"


def _gather(source, stdio, http, git) -> ScanContext:
    """Build a ScanContext from whichever input was supplied."""
    from . import sources as src

    tools: list[ToolInfo] = []
    source_files: list[Path] = []
    config_files: list[Path] = []
    root: Path | None = None
    label = source or stdio or http or git or "unknown"

    if git:
        root = src.clone_repo(git)
        source_files, config_files = src.enumerate_sources(root)
    elif source:
        root = Path(source)
        source_files, config_files = src.enumerate_sources(root)

    if stdio:
        from .connect import introspect_stdio
        tools = introspect_stdio(stdio)
    elif http:
        from .connect import introspect_http
        tools = introspect_http(http)

    return ScanContext(server_label=str(label), tools=tools,
                       source_files=source_files, config_files=config_files, root=root)


def _run_detectors(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for det in ALL_DETECTORS:
        findings.extend(det.scan(ctx))
    return findings


@app.command()
def scan(
    source: str = typer.Argument(None, help="Path to a server directory (pre-install)."),
    stdio: str = typer.Option(None, help="Spawn a stdio server, e.g. 'python server.py'."),
    http: str = typer.Option(None, help="Streamable-HTTP server URL."),
    git: str = typer.Option(None, help="Git URL to shallow-clone and scan."),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON to stdout."),
    report: str = typer.Option(None, help="Write a markdown report to this path."),
    fail_on: str = typer.Option("none", help="Exit non-zero at/above this severity: none|low|medium|high|critical."),
    llm: bool = typer.Option(False, "--llm", help="Add a local LLM second opinion (Ollama). Off by default."),
    cloud: bool = typer.Option(False, "--cloud", help="Use a hosted model for --llm. Snippets leave your machine (loud)."),
    llm_model: str = typer.Option("llama3", help="Model name for the --llm second-opinion pass."),
):
    """Scan an MCP server."""
    if not any([source, stdio, http, git]):
        typer.echo("Provide a path, --stdio, --http, or --git. See --help.", err=True)
        raise typer.Exit(2)

    ctx = _gather(source, stdio, http, git)
    findings = _run_detectors(ctx)

    from .allowlist import load_allowlist
    allow = load_allowlist(ctx.root)
    suppressed = 0
    if allow:
        kept = [f for f in findings if f.fingerprint() not in allow]
        suppressed = len(findings) - len(kept)
        findings = kept

    if llm or cloud:
        from .llm import LLMConfig, annotate
        annotate(findings, LLMConfig(enabled=True, cloud=cloud, model=llm_model))

    from . import report as rep
    if json_out:
        typer.echo(rep.to_json(findings, ctx.server_label, suppressed))
    else:
        rep.print_table(findings, ctx.server_label, suppressed)
    if report:
        Path(report).write_text(rep.to_markdown(findings, ctx.server_label, suppressed),
                                encoding="utf-8")
        if not json_out:
            typer.echo(f"\nReport written to {report}")

    thresholds = {"none": None, "low": Severity.LOW, "medium": Severity.MEDIUM,
                  "high": Severity.HIGH, "critical": Severity.CRITICAL}
    thr = thresholds.get(fail_on.lower())
    if thr is not None and any(f.severity >= thr for f in findings):
        raise typer.Exit(1)


def _baseline_path(label: str) -> Path:
    h = hashlib.sha256(label.encode()).hexdigest()[:16]
    return _BASELINE_DIR / f"{h}.json"


def _tool_hashes(tools: list[ToolInfo]) -> dict[str, str]:
    return {
        t.name: hashlib.sha256(
            (t.description + json.dumps(t.input_schema, sort_keys=True)).encode()
        ).hexdigest()
        for t in tools
    }


@app.command()
def baseline(stdio: str = typer.Option(None), http: str = typer.Option(None)):
    """Record a tool-definition hash baseline for rug-pull detection."""
    ctx = _gather(None, stdio, http, None)
    _BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    path = _baseline_path(ctx.server_label)
    path.write_text(json.dumps(_tool_hashes(ctx.tools), indent=2), encoding="utf-8")
    typer.echo(f"Baselined {len(ctx.tools)} tools -> {path}")


@app.command()
def diff(stdio: str = typer.Option(None), http: str = typer.Option(None)):
    """Compare current tool definitions against the stored baseline (rug-pull check)."""
    ctx = _gather(None, stdio, http, None)
    path = _baseline_path(ctx.server_label)
    if not path.exists():
        typer.echo("No baseline. Run `mcp-audit baseline` first.", err=True)
        raise typer.Exit(2)
    old = json.loads(path.read_text(encoding="utf-8"))
    new = _tool_hashes(ctx.tools)
    changed = [n for n in new if n in old and old[n] != new[n]]
    added = [n for n in new if n not in old]
    removed = [n for n in old if n not in new]
    if not (changed or added or removed):
        typer.echo("No drift. Tool definitions match baseline.")
        return
    for n in changed:
        typer.echo(f"CHANGED: {n}  (possible rug-pull)")
    for n in added:
        typer.echo(f"ADDED:   {n}")
    for n in removed:
        typer.echo(f"REMOVED: {n}")
    raise typer.Exit(1)


@app.command()
def allow(
    fingerprint: str = typer.Argument(..., help="Finding fingerprint to suppress (from --json/--report)."),
    root: str = typer.Option(None, help="Project root holding .mcp-audit/allowlist (default: cwd)."),
):
    """Suppress a finding as a false positive by adding its fingerprint to the allowlist."""
    from .allowlist import add_to_allowlist
    target = add_to_allowlist(fingerprint, Path(root) if root else None)
    typer.echo(f"Allowlisted {fingerprint} -> {target}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
