import pytest

from pathlib import Path
from php_vuln_scanner.cli import EXIT_CLEAN, EXIT_ERROR, main


def test_scan_existing_path_is_clean(tmp_path: Path) -> None:
    assert main(["scan", str(tmp_path)]) == EXIT_CLEAN


def test_scan_missing_path_is_error(tmp_path: Path) -> None:
    assert main(["scan", str(tmp_path / "does-not-exist")]) == EXIT_ERROR


def test_modules_list_runs(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["modules", "list"]) == EXIT_CLEAN
    assert capsys.readouterr().out.strip()


def test_no_command_prints_help_and_clean_exit() -> None:
    assert main([]) == EXIT_CLEAN


def test_prints_version_and_clean_exit() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == EXIT_CLEAN
