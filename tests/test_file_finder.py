from __future__ import annotations

from pathlib import Path
from php_vuln_scanner.config import CoreConfig
from php_vuln_scanner.file_finder import find_php_files


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("<?php\n")
    return path


def test_finds_php_variants_and_skips_non_php_files(tmp_path: Path) -> None:
    _touch(tmp_path / "index.php")
    _touch(tmp_path / "legacy.php5")
    _touch(tmp_path / "template.phtml")
    _touch(tmp_path / "style.css")
    _touch(tmp_path / "text.txt")

    found = find_php_files(tmp_path, CoreConfig())
    assert [p.name for p in found] == ["index.php", "legacy.php5", "template.phtml"]


def test_excluded_dirs_are_skipped(tmp_path: Path) -> None:
    _touch(tmp_path / "app" / "main.php")
    _touch(tmp_path / "vendor" / "lib.php")
    _touch(tmp_path / "app" / "vendor" / "nested.php")

    found = find_php_files(tmp_path, CoreConfig())
    assert [p.name for p in found] == ["main.php"]


def test_single_file_target_is_returned_as_is(tmp_path: Path) -> None:
    target = _touch(tmp_path / "return_me.txt")
    assert find_php_files(target, CoreConfig()) == [target]


def test_results_are_sorted(tmp_path: Path) -> None:
    _touch(tmp_path / "b.php")
    _touch(tmp_path / "a.php")
    found = find_php_files(tmp_path, CoreConfig())
    assert found == sorted(found)
