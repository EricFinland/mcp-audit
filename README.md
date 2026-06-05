# mcp-audit

> **Scan an MCP server before you trust it.** Local-first security auditing for the Model
> Context Protocol: tool poisoning, hardcoded secrets, command injection, and supply-chain
> risks, mapped to the OWASP MCP Top 10. **Nothing leaves your machine.**

[![PyPI](https://img.shields.io/badge/pypi-mcp--audit-blue)](#) · MIT · Python 3.11+

---

## Why

MCP turned every connected server into a trust boundary your agent reads as authoritative.
Tool descriptions are text the model obeys, so a malicious server can hide instructions a
human never sees. The existing scanners are good, but the leading one **sends your tool
descriptions to a vendor API** for classification. That's a non-starter when your servers are
wired to private infra.

**mcp-audit is local-first.** Static heuristics and AST analysis run entirely on your
machine. The optional LLM second-opinion pass uses a **local model via Ollama** by default;
cloud is strictly opt-in and loudly flagged.

It's **pre-install first**: point it at a repo, package, or directory and get a verdict
*before* the server ever touches your agent.

## Install

```bash
uvx mcp-audit --help          # zero-install run
# or
pip install mcp-audit
```

## Use

```bash
# Pre-install: analyze a server's source + declared tools before trusting it
mcp-audit scan ./path/to/server --report report.md
mcp-audit scan --git https://github.com/owner/repo

# Introspect a running / spawnable server's tool surface (introspection only, never calls tools)
mcp-audit scan --stdio "python server.py" --json
mcp-audit scan --http http://localhost:8000/mcp

# Rug-pull drift detection
mcp-audit baseline --stdio "python server.py"
mcp-audit diff     --stdio "python server.py"

# CI gate
mcp-audit scan ./server --fail-on high

# Optional local LLM second opinion (Ollama; nothing leaves your machine). --cloud opts in loudly.
mcp-audit scan ./server --llm

# Suppress a confirmed false positive by its fingerprint (shown in --json and --report)
mcp-audit allow <fingerprint>
```

### Try it on the bundled poisoned fixture

```bash
mcp-audit scan --stdio "python fixtures/evil_server.py"
mcp-audit scan ./fixtures        # source-level scan (catches the command-injection sink)
```

## What it detects

Seven detectors. Every finding carries an OWASP MCP Top 10 id, a severity, a confidence level,
and a stable fingerprint you can whitelist (`mcp-audit allow <fingerprint>`) when it is a false
positive. See [`sample_report.md`](sample_report.md) for real output against the bundled fixtures.

| OWASP | Risk | Coverage |
|---|---|---|
| MCP03 | Tool Poisoning | ✅ full |
| MCP04 | Supply Chain / Dependency Tampering | 🟡 partial (hygiene) |
| MCP01 | Token Mismanagement / Secret Exposure | 🟡 partial |
| MCP05 | Command Injection | 🟡 partial (AST) |
| MCP06 | Intent Flow Subversion | 🟡 partial |
| MCP09 | Shadow MCP Servers | 🟡 partial |
| MCP10 | Context Over-Sharing | 🟡 partial |
| MCP02 / MCP07 / MCP08 | Scope creep / Auth / Telemetry | ❌ needs runtime + identity |

**A clean static scan does not prove a server is safe.** It cannot catch post-install
rug-pulls (use `baseline`/`diff`), runtime auth failures, or scope creep. Pair with a runtime
proxy and an identity gateway for defense in depth. Honesty about coverage is a feature.

## As a Claude skill

`skill/SKILL.md` lets Claude run the audit in-loop: "before I add this MCP server, scan it."

## Status

Early and under active development. Detectors are v0 heuristics with per-finding confidence
levels; tune the HIGH bar conservatively before pointing it at servers you don't control.

## License

MIT. Built by [Eric Catalano](https://ericcatalano.dev).
