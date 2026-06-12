# Changelog

## 0.2.0

- **Security grade.** Every scan now produces an A-F letter grade and a 0-100 score, shown
  in the terminal, JSON, markdown, and HTML outputs. Deterministic and explainable:
  critical -40, high -15, medium -5, low -1.
- **SARIF output.** `--sarif file.sarif` writes SARIF 2.1.0 with per-finding fingerprints,
  ready for GitHub Code Scanning upload.
- **HTML report.** `--html report.html` writes a self-contained dark-themed report with the
  grade, full findings detail, and the coverage matrix. No external assets.
- **JavaScript / TypeScript command-injection detection.** The MCP05 detector now covers
  the bulk of the MCP ecosystem: `child_process` exec/execSync with dynamic commands,
  `spawn(..., {shell: true})`, and `eval` / `new Function`. Conservative by design:
  bare `exec(` only counts when the file imports child_process, so `regex.exec()` never fires.
- **Expanded secret patterns.** GitLab PATs, npm tokens, Hugging Face tokens, Slack webhook
  URLs, SendGrid keys, Twilio API key SIDs, Azure storage account keys, JWTs, and OpenAI
  project keys, all behind the existing placeholder and test-path false-positive guards.
- **`corpus` command.** Scan many servers (local paths or git URLs) from a targets file and
  aggregate one table with per-target grades. The methodology behind published mcp-audit
  reports, reproducible in one command. Exits non-zero if any target has a high or critical.
- **`inspect` command.** Dump a server's declared tool surface as JSON, introspection only.
- **`--exclude` flag.** Skip files whose path contains a substring (repeatable).
- **CI.** Test matrix on Ubuntu and Windows, Python 3.11 and 3.12, plus a fixture smoke scan.

## 0.1.0

- Initial release: tool poisoning (MCP03), hardcoded secrets (MCP01), Python AST command
  injection (MCP05), supply-chain hygiene (MCP04), shadow-MCP inventory (MCP09), intent-flow
  injection corpus (MCP06), context over-sharing (MCP10).
- Live stdio/HTTP introspection via the MCP SDK (introspection only, never invokes a tool).
- Rich terminal, JSON, and markdown reports with an explicit coverage and limitations section.
- Per-finding fingerprints with an allowlist (`mcp-audit allow`) for false-positive control.
- Loadable YAML pattern packs for the poisoning and injection rules.
- Optional local LLM second opinion via Ollama (off by default; `--cloud` is loud and opt-in).
- Baseline / diff rug-pull drift detection plus a GitHub Action canary.
