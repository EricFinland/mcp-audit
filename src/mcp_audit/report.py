"""Render findings as a rich terminal table, JSON, markdown, SARIF, or HTML."""
from __future__ import annotations

import html as _html
import json
import re
from collections import Counter

from .detectors.base import Finding, Severity
from .owasp import OWASP_MCP, label

_SEV_COLOR = {
    "CRITICAL": "bold white on red", "HIGH": "bold red",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}

def grade(findings: list[Finding]) -> tuple[str, int]:
    """Letter grade + 0-100 score for a scan. Simple, explainable, deterministic.

    Weights: critical -40, high -15 (uncapped: severe findings should tank the score).
    Medium is capped at -25 total and low at -10 total so a large monorepo's hygiene
    volume cannot drown the severity profile. A scan with zero critical and zero high
    findings never grades below C: hygiene alone is not a failing offense.
    """
    crit = sum(1 for f in findings if f.severity is Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity is Severity.HIGH)
    med = sum(1 for f in findings if f.severity is Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity is Severity.LOW)
    score = 100 - 40 * crit - 15 * high - min(25, 5 * med) - min(10, low)
    score = max(0, score)
    if crit == 0 and high == 0:
        score = max(score, 70)
    letter = ("A" if score >= 90 else "B" if score >= 80 else
              "C" if score >= 70 else "D" if score >= 60 else "F")
    return letter, score


def to_json(findings: list[Finding], server: str, suppressed: int = 0) -> str:
    letter, score = grade(findings)
    return json.dumps(
        {"server": server, "count": len(findings), "suppressed": suppressed,
         "grade": letter, "score": score,
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
    letter, score = grade(findings)
    g_style = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold white on red"}[letter]
    console.print(f"\n[bold]{len(findings)} findings[/bold]   {summary}   "
                  f"grade [{g_style}] {letter} [/{g_style}] ({score}/100)")
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
    letter, score = grade(findings)
    lines = [f"# mcp-audit report: `{server}`", ""]
    counts = Counter(str(f.severity) for f in findings)
    lines.append(f"**Grade: {letter} ({score}/100)** · **{len(findings)} findings** ("
                 + (", ".join(f"{k}: {counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[k]) or "none above INFO")
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
                      f"- **Fix:** {f.recommendation}"]
            if f.llm_note:
                lines.append(f"- **LLM second opinion:** {f.llm_note}")
            lines += [f"- **Fingerprint:** `{f.fingerprint()}` "
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


# --- SARIF 2.1.0 (GitHub Code Scanning et al.) --------------------------------------

_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error",
                Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
_LOC_RE = re.compile(r"^(?P<path>.+?):(?P<line>\d+)")


def to_sarif(findings: list[Finding], server: str) -> str:
    """Render findings as SARIF 2.1.0 so they upload straight into code-scanning UIs."""
    from . import __version__

    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.id not in rules:
            rules[f.id] = {
                "id": f.id,
                "shortDescription": {"text": f.title},
                "helpUri": "https://github.com/EricFinland/mcp-audit",
                "properties": {"owasp_mcp": f.owasp_id},
            }
        loc = {"physicalLocation": {"artifactLocation": {"uri": "(declared-tool-surface)"}}}
        m = _LOC_RE.match(f.location)
        if m:
            uri = m.group("path").replace("\\", "/")
            loc = {"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": int(m.group("line"))},
            }}
        results.append({
            "ruleId": f.id,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.title}. {f.recommendation}"},
            "locations": [loc],
            "partialFingerprints": {"mcpAudit/v1": f.fingerprint()},
            "properties": {"owasp_mcp": f.owasp_id, "confidence": str(f.confidence),
                           "evidence": f.evidence},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcp-audit",
                "informationUri": "https://github.com/EricFinland/mcp-audit",
                "version": __version__,
                "rules": list(rules.values()),
            }},
            "properties": {"server": server},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


# --- Single-file HTML report ---------------------------------------------------------

_HTML_SEV_COLOR = {"CRITICAL": "#ff5470", "HIGH": "#ff8c5a", "MEDIUM": "#eab308",
                   "LOW": "#38bdf8", "INFO": "#8b8b9e"}


def to_html(findings: list[Finding], server: str, suppressed: int = 0) -> str:
    """Self-contained dark-themed HTML report. No external assets, safe to share."""
    letter, score = grade(findings)
    counts = Counter(str(f.severity) for f in findings)
    e = _html.escape
    grade_color = {"A": "#34d399", "B": "#a3e635", "C": "#eab308",
                   "D": "#fb923c", "F": "#ff5470"}[letter]

    rows = []
    for f in sorted(findings, key=lambda x: x.severity, reverse=True):
        sev = str(f.severity)
        rows.append(
            f"<tr><td><span class='sev' style='background:{_HTML_SEV_COLOR[sev]}22;"
            f"color:{_HTML_SEV_COLOR[sev]};border:1px solid {_HTML_SEV_COLOR[sev]}55'>{sev}</span></td>"
            f"<td class='mono'>{e(f.owasp_id)}</td><td>{e(f.title)}</td>"
            f"<td class='mono loc'>{e(f.location)}</td><td>{e(str(f.confidence))}</td></tr>"
            f"<tr class='detail'><td colspan='5'><div class='evidence'>{e(f.evidence)}</div>"
            f"<div class='fix'>{e(f.recommendation)}</div>"
            f"<div class='fp mono'>fingerprint {e(f.fingerprint())}"
            + (f" · LLM: {e(f.llm_note)}" if f.llm_note else "") + "</div></td></tr>"
        )

    cov_rows = []
    cov_label = {"full": ("full", "#34d399"), "partial": ("partial", "#eab308"),
                 "out_of_scope": ("out of scope", "#8b8b9e")}
    for oid, meta in OWASP_MCP.items():
        text, color = cov_label[meta["coverage"]]
        cov_rows.append(f"<tr><td class='mono'>{e(oid)}</td><td>{e(meta['title'])}</td>"
                        f"<td style='color:{color}'>{text}</td></tr>")

    summary = " · ".join(f"{k} {counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts[k]) or "no findings"
    suppressed_note = f"<p class='dim'>{suppressed} finding(s) suppressed by allowlist.</p>" if suppressed else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcp-audit · {e(server)}</title>
<style>
  :root {{ --bg:#0b0b0f; --surface:#15151c; --border:#26262f; --text:#e8e8f0; --muted:#9c9cae; --accent:#818cf8; }}
  * {{ box-sizing:border-box; margin:0; }}
  body {{ background:var(--bg); color:var(--text); font:15px/1.6 'Segoe UI',system-ui,sans-serif; padding:2.5rem 1rem; }}
  main {{ max-width:1000px; margin:0 auto; }}
  .mono {{ font-family:Consolas,'Courier New',monospace; font-size:.86em; }}
  header {{ display:flex; align-items:center; gap:1.5rem; flex-wrap:wrap; margin-bottom:2rem; }}
  .gradebox {{ width:84px; height:84px; border-radius:14px; display:flex; align-items:center; justify-content:center;
              font-size:2.6rem; font-weight:700; color:{grade_color}; background:{grade_color}18; border:2px solid {grade_color}66; }}
  h1 {{ font-size:1.5rem; }} h2 {{ font-size:1.1rem; margin:2.2rem 0 .8rem; color:var(--accent); }}
  .dim {{ color:var(--muted); }}
  table {{ width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); border-radius:10px; overflow:hidden; }}
  th,td {{ padding:.55rem .8rem; text-align:left; border-top:1px solid var(--border); vertical-align:top; }}
  th {{ background:#1b1b24; font-size:.8rem; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }}
  .sev {{ padding:.12rem .55rem; border-radius:99px; font-size:.74rem; font-weight:600; letter-spacing:.04em; }}
  .loc {{ color:var(--muted); word-break:break-all; }}
  tr.detail td {{ border-top:none; padding-top:0; }}
  .evidence {{ font-family:Consolas,monospace; font-size:.82rem; background:#0e0e14; border:1px solid var(--border);
               border-radius:6px; padding:.45rem .7rem; color:#fca5a5; margin:.2rem 0 .45rem; word-break:break-all; }}
  .fix {{ font-size:.88rem; color:var(--muted); }}
  .fp {{ font-size:.74rem; color:#5c5c6e; margin-top:.35rem; }}
  footer {{ margin-top:2.5rem; color:var(--muted); font-size:.85rem; border-top:1px solid var(--border); padding-top:1.2rem; }}
  a {{ color:var(--accent); }}
</style></head>
<body><main>
<header>
  <div class="gradebox">{letter}</div>
  <div>
    <h1>mcp-audit report</h1>
    <div class="mono dim">{e(server)}</div>
    <div>{len(findings)} findings · {e(summary)} · score {score}/100</div>
  </div>
</header>
{suppressed_note}
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>OWASP</th><th>Finding</th><th>Location</th><th>Confidence</th></tr></thead>
<tbody>{''.join(rows) if rows else "<tr><td colspan='5' class='dim'>No findings.</td></tr>"}</tbody></table>
<h2>Coverage and limitations</h2>
<p class="dim">mcp-audit is a pre-install static scanner. A clean scan does not prove a server is safe:
it cannot catch rug-pulls (use baseline/diff), runtime auth failures (MCP07), scope creep (MCP02), or telemetry gaps (MCP08).</p>
<table><thead><tr><th>OWASP</th><th>Risk</th><th>Coverage</th></tr></thead><tbody>{''.join(cov_rows)}</tbody></table>
<footer>Generated by <a href="https://github.com/EricFinland/mcp-audit">mcp-audit</a> · local-first, nothing leaves your machine.</footer>
</main></body></html>"""
