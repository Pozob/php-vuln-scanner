import pytest

from php_vuln_scanner.cli import main, EXIT_CLEAN

def test_no_command_prints_help_and_clean_exit() -> None:
    assert main([]) == EXIT_CLEAN


def test_prints_version_and_clean_exit() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == EXIT_CLEAN
