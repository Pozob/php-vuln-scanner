"""Tests for JSON/terminal/HTML reporting (Kickstart §7)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from php_vuln_scanner.cli import EXIT_FINDINGS, main
from php_vuln_scanner.scanner import run_scan
from php_vuln_scanner.reporting import build_report,  render_terminal, write_json_report, render_html

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
MODULES_DIR = REPO_ROOT / "modules"


@pytest.fixture(scope="module")
def result():
    return run_scan(FIXTURES, modules_dir=MODULES_DIR)


@pytest.fixture(scope="module")
def report(result):
    return build_report(result)


# region json report
def test_report_contains_metadata(report) -> None:
    assert report["scanner"]["name"] == "phpscan"
    assert report["scanner"]["version"] != "unknown"
    assert report["timestamp"].startswith("20")
    assert report["target"].endswith("fixtures")
    assert {mod["id"] for mod in report["modules"]} == {
        "a02_misconfiguration", "a04_crypto_failures", "a05_injection",
    }
    assert all("version" in mod for mod in report["modules"])


def test_report_contains_effective_config(report) -> None:
    assert "php_extensions" in report["effective_config"]["core"]
    assert "taint_model" in report["effective_config"]["modules"]["a05_injection"]


def test_report_count_matches(report) -> None:
    assert report["summary"]["total_findings"] == len(report["findings"])
    assert sum(report["summary"]["by_severity"].values()) == len(report["findings"])
    assert sum(report["summary"]["by_category"].values()) == len(report["findings"])


def test_report_findings_follow_schema(report) -> None:
    finding = next(f for f in report["findings"] if f["rule_id"] == "A05-SQLI-001")
    assert finding["cwe"] == "CWE-89"
    assert finding["severity"] == "high"
    assert finding["file"] == "sqli_legacy.php"
    assert finding["remediation"]
    assert finding["taint_trace"][0]["description"].startswith("user input")


def test_json_report_roundtrips(report, tmp_path: Path) -> None:
    path = tmp_path / "out.json"
    write_json_report(report, path)
    assert json.loads(path.read_text()) == json.loads(json.dumps(report))

# endregion


# region HTML
def test_terminal_summary_groups_and_counts(result) -> None:
    out = render_terminal(result)
    assert "by category:" in out
    assert "A05:2025" in out and "A04:2025" in out and "A02:2025" in out
    assert "high severity:" in out
    assert "sqli_legacy.php:5" in out


def test_terminal_clean_scan(tmp_path: Path) -> None:
    (tmp_path / "ok.php").write_text("<?php echo 'hi';")
    out = render_terminal(run_scan(tmp_path, modules_dir=MODULES_DIR))
    assert "No findings. Clean scan" in out

# endregion

# region HTML
def test_html_is_self_contained_and_complete(report) -> None:
    page = render_html(report)
    assert page.startswith("<!DOCTYPE html>")
    assert "<style>" in page  # inline CSS
    assert "http://" not in page and "https://" not in page  # no external resources
    assert "A05-SQLI-001" in page
    assert "Remediation:" in page
    assert "Taint trace:" in page


def test_html_escapes_code_content(tmp_path: Path) -> None:
    (tmp_path / "evil.php").write_text('<?php echo $_GET["<script>alert(1)</script>"];')
    page = render_html(build_report(run_scan(tmp_path, modules_dir=MODULES_DIR)))
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page

# endregion


def test_cli_json_format_with_output(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    out_file = tmp_path / "result.json"
    assert main(["scan", str(FIXTURES), "--format", "json", "--output", str(out_file)]) == EXIT_FINDINGS
    assert json.loads(out_file.read_text())["scanner"]["name"] == "phpscan"
