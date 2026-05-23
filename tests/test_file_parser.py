from __future__ import annotations

from pathlib import Path
from php_vuln_scanner.file_parser import ParsedFile, ParsingService

OLD_PHP_CODE = b"""<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
$result = mysql_query($query) or die(mysql_error());
echo $row['first_name'];
?>
"""


def _parse(source: bytes) -> tuple[ParsingService, ParsedFile]:
    service = ParsingService()
    return service, service.parse_source(source, Path("temp.php"), "temp.php")


def test_parses_old_php() -> None:
    _, pf = _parse(OLD_PHP_CODE)
    assert pf.root.type == "program"
    assert not pf.has_parse_errors


def test_broken_php_yields_tree_with_errors__but_no_crash() -> None:
    _, pf = _parse(b"<?php if ($x { echo 'unclosed'; ")
    assert pf.has_parse_errors
    assert pf.root.child_count > 0


def test_html_php_mix_parses() -> None:
    _, pf = _parse(b"<html><body><?php echo $name; ?></body></html>")
    assert not pf.has_parse_errors


def test_query_captures_find_function_calls() -> None:
    service, pf = _parse(OLD_PHP_CODE)
    captures = service.captures(pf.root, "(function_call_expression function: (name) @fn)")
    names = sorted(pf.text(node) for node in captures["fn"])
    assert names == ["die", "mysql_error", "mysql_query"]


def test_text_line_and_snippet_helpers() -> None:
    service, pf = _parse(OLD_PHP_CODE)
    captures = service.captures(pf.root, "(function_call_expression function: (name) @fn)")
    mysql_query = next(n for n in captures["fn"] if pf.text(n) == "mysql_query")
    assert pf.line(mysql_query) == 4
    assert pf.snippet(mysql_query) == '$result = mysql_query($query) or die(mysql_error());'


def test_unreadable_file_is_skipped_with_warning(tmp_path: Path, caplog) -> None:
    missing = tmp_path / "not-existing.php"
    result = ParsingService().parse_file(missing, tmp_path)
    assert result is None
    assert "skipping unreadable file" in caplog.text


def test_parse_files_continues_past_unreadable(tmp_path: Path) -> None:
    good = tmp_path / "good.php"
    good.write_bytes(b"<?php echo 1;")
    parsed = ParsingService().parse_files([tmp_path / "gone.php", good], tmp_path)
    assert [pf.rel_path for pf in parsed] == ["good.php"]
