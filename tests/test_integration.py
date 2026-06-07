from __future__ import annotations

from pathlib import Path
from php_vuln_scanner.cli import main, EXIT_CLEAN, EXIT_FINDINGS
from php_vuln_scanner.scanner import run_scan

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
MODULES_DIR = REPO_ROOT / "modules"

EXPECTED_FINDINGS = {
    ("sqli_legacy.php", "A05-SQLI-001", 5),
    ("xss_reflected.php", "A05-XSS-001", 4),
    ("cmd_injection.php", "A05-CMD-001", 4),
    ("include_eval.php", "A05-FILE-001", 4),
    ("include_eval.php", "A05-CODE-001", 5),
}
CLEAN_FILES = {"clean_prepared.php", "clean_sanitized.php"}


def test_scan_matches_expected_findings() -> None:
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR)
    found = {(f.file, f.rule_id, f.line) for f in result.findings}
    assert found == EXPECTED_FINDINGS


def test_clean_fixtures_stay_clean() -> None:
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR)
    assert not [finding for finding in result.findings if finding.file in CLEAN_FILES]


def test_findings_have_remediation_and_trace() -> None:
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR)
    for finding in result.findings:
        assert finding.remediation.strip()
        assert finding.taint_trace, f"{finding.rule_id} should carry a taint trace"
        assert finding.snippet.strip()


def test_module_filter_limits_scan() -> None:
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR, only_modules={"module_does_not_exist"})
    assert result.modules == []
    assert result.findings == []


def test_cli_exit_codes(tmp_path: Path, capsys) -> None:
    assert main(["scan", str(FIXTURES)]) == EXIT_FINDINGS

    clean_dir = tmp_path / "clean"
    clean_dir.mkdir()
    (clean_dir / "ok.php").write_text("<?php echo 'static';\n")
    assert main(["scan", str(clean_dir)]) == EXIT_CLEAN
    capsys.readouterr()


def test_modules_list_shows_a05(capsys) -> None:
    assert main(["modules", "list"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "a05_injection" in out
    assert "taint-based" in out
    assert "A05-SQLI-001" in out
