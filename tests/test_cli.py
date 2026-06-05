"""CLI smoke tests: exit codes and output shape for scan / report / json / allow."""
import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_audit.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _json(text: str) -> dict:
    return json.loads(text[text.index("{"): text.rindex("}") + 1])


def test_scan_requires_a_target():
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 2


def test_scan_evil_pkg_reports_mcp04():
    result = runner.invoke(app, ["scan", str(FIXTURES / "evil_pkg")])
    assert result.exit_code == 0
    assert "MCP04" in result.stdout


def test_scan_json_shape():
    result = runner.invoke(app, ["scan", str(FIXTURES / "evil_pkg"), "--json"])
    assert result.exit_code == 0
    data = _json(result.stdout)
    assert data["count"] >= 1
    assert "suppressed" in data
    assert all("fingerprint" in f for f in data["findings"])


def test_fail_on_high_exits_nonzero_when_high_present():
    result = runner.invoke(app, ["scan", str(FIXTURES / "evil_pkg"), "--fail-on", "high"])
    assert result.exit_code == 1


def test_fail_on_high_exits_zero_when_clean():
    result = runner.invoke(app, ["scan", str(FIXTURES / "clean_pkg"), "--fail-on", "high"])
    assert result.exit_code == 0


def test_report_is_written_with_coverage_section(tmp_path):
    out = tmp_path / "report.md"
    result = runner.invoke(app, ["scan", str(FIXTURES / "evil_pkg"), "--report", str(out)])
    assert result.exit_code == 0
    text = out.read_text(encoding="utf-8")
    assert "Coverage & limitations" in text
    assert "MCP04" in text


def test_allow_command_writes_allowlist(tmp_path):
    result = runner.invoke(app, ["allow", "deadbeef1234", "--root", str(tmp_path)])
    assert result.exit_code == 0
    entries = (tmp_path / ".mcp-audit" / "allowlist").read_text(encoding="utf-8").split()
    assert "deadbeef1234" in entries
