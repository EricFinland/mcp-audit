---
name: mcp-audit
description: >
  Audit an MCP server for security risks BEFORE trusting or installing it. Use whenever the
  user is about to add, install, or connect a new MCP server, shares an MCP server repo/URL,
  or asks "is this MCP server safe?". Runs a local-first static scan for tool poisoning,
  hardcoded secrets, command injection, and supply-chain issues, mapped to the OWASP MCP
  Top 10. Nothing leaves the machine.
---

# mcp-audit skill

When the user wants to vet an MCP server, run `mcp-audit` and summarize the findings.

## When to use
- "Should I install this MCP server?" / "Is this server safe?"
- The user pastes a GitHub repo or package for an MCP server.
- Before wiring any new server into a client config.

## How to run

Pre-install scan of a local directory or git repo (preferred, no execution of the server):
```
mcp-audit scan ./path/to/server --report /tmp/mcp-audit.md
mcp-audit scan --git https://github.com/owner/repo --report /tmp/mcp-audit.md
```

Introspect a running/spawnable server's declared tool surface:
```
mcp-audit scan --stdio "python server.py" --json
mcp-audit scan --http http://localhost:8000/mcp --json
```

Rug-pull drift check (after a baseline exists):
```
mcp-audit baseline --stdio "python server.py"
mcp-audit diff --stdio "python server.py"
```

## How to report back
1. Lead with the worst severity (CRITICAL/HIGH) and its OWASP ID.
2. Quote the offending tool/description location and the recommended fix.
3. **Always state the limitation:** a clean static scan does not prove safety; it cannot
   catch runtime auth gaps (MCP07), scope creep (MCP02), or post-install rug-pulls.
4. If anything is CRITICAL/HIGH, advise against installing until resolved or disclosed.
5. If a finding is a clear false positive, note its fingerprint (shown in `--json`/`--report`);
   the user can suppress it with `mcp-audit allow <fingerprint>`.

## Privacy note
mcp-audit is local-first. Only run with `--cloud` if the user explicitly opts in, and tell
them snippets will leave the machine if they do.
