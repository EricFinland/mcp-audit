"""CLI smoke tests: exit codes and output shape for scan / report / json / allow."""
import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_audit.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _json(text: str) -> dict:
    return json.loads(text[text.index("{"): text.rindex("}") + 1])


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "mcp-audit" in result.stdout


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


def test_json_includes_grade_and_score():
    result = runner.invoke(app, ["scan", str(FIXTURES / "evil_pkg"), "--json"])
    data = _json(result.stdout)
    assert data["grade"] in "ABCDF"
    assert 0 <= data["score"] <= 100


def test_sarif_output_is_valid_and_mapped(tmp_path):
    out = tmp_path / "scan.sarif"
    result = runner.invoke(app, ["scan", str(FIXTURES / "evil_pkg"), "--sarif", str(out)])
    assert result.exit_code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-audit"
    assert run["results"], "expected SARIF results"
    assert all("ruleId" in r and "level" in r for r in run["results"])
    assert any(r["level"] == "error" for r in run["results"])  # the HIGH postinstall


def test_html_report_is_written(tmp_path):
    out = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(FIXTURES / "evil_pkg"), "--html", str(out)])
    assert result.exit_code == 0
    text = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in text
    assert "MCP04" in text
    assert "Coverage and limitations" in text


def test_exclude_flag_skips_paths():
    base = runner.invoke(app, ["scan", str(FIXTURES / "evil_pkg"), "--json"])
    excl = runner.invoke(app, ["scan", str(FIXTURES / "evil_pkg"), "--json",
                               "--exclude", "package.json"])
    assert _json(base.stdout)["count"] > 0
    assert _json(excl.stdout)["count"] == 0


def test_corpus_command_aggregates_targets(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text(
        f"# corpus smoke test\n{FIXTURES / 'evil_pkg'}\n{FIXTURES / 'clean_pkg'}\n",
        encoding="utf-8",
    )
    out = tmp_path / "corpus.md"
    result = runner.invoke(app, ["corpus", str(targets), "--out", str(out)])
    assert result.exit_code == 1  # evil_pkg has a HIGH, corpus gates on it
    table = out.read_text(encoding="utf-8")
    assert "evil_pkg" in table and "clean_pkg" in table
    assert "Scanned 2 of 2 targets" in table
