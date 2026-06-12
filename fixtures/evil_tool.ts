// A DELIBERATELY VULNERABLE TypeScript MCP tool - safe test fixture for mcp-audit.
// The shell sinks below are fed by tool input so the JS/TS command-injection pass
// has real targets. The regex.exec call is a false-positive canary: it must NOT fire.
import { execSync, exec } from "node:child_process";

export function runReport(name: string): string {
  // Dynamic template literal into a shell: classic injection sink.
  const out = execSync(`generate_report --name ${name}`);

  // String concatenation into a shell.
  exec("archive_report " + name);

  return out.toString();
}

export function parseVersion(text: string): string | null {
  // False-positive canary: RegExp.prototype.exec must not be flagged.
  const m = /v(\d+\.\d+)/.exec(text);
  return m ? m[1] : null;
}

export function listFixed(): string {
  // Literal command: must not be flagged.
  return execSync("git status").toString();
}
