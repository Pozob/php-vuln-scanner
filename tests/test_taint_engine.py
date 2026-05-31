from __future__ import annotations

import pytest
from pathlib import Path
from php_vuln_scanner.file_parser import ParsingService
from php_vuln_scanner.taint_engine import TaintEngine, TaintFlow, TaintModel

MODEL = TaintModel.from_dict(
    {
        "sources": ["$_GET", "$_POST", "$_COOKIE", "$_SERVER", "$_FILES"],
        "sinks": {
            "sql": ["mysql_query", "mysqli_query", "PDO::query"],
            "xss": ["echo", "print"],
            "command": ["exec", "system", "shell_exec", "passthru"],
            "file_inclusion": ["include", "require", "include_once", "require_once"],
        },
        "sanitizers": {
            "sql": ["mysqli_real_escape_string", "prepared statements (PDO::prepare / mysqli_prepare)"],
            "xss": ["htmlspecialchars", "htmlentities"],
            "command": ["escapeshellarg", "escapeshellcmd"],
        },
    }
)


def _analyze(php: str) -> list[TaintFlow]:
    service = ParsingService()
    parsed = service.parse_source(php.encode(), Path("temp.php"), "temp.php")
    assert not parsed.has_parse_errors, "test fixture must be valid PHP"
    return TaintEngine(MODEL).analyze_file(parsed)


def test_directly_to_sink() -> None:
    (flow,) = _analyze("<?php echo $_GET['name'];")
    assert (flow.sink_type, flow.sink_name, flow.source) == ("xss", "echo", "$_GET")


def test_clean_code() -> None:
    assert _analyze("<?php $name = 'world'; echo $name;") == []


def test_assignment() -> None:
    (flow,) = _analyze("<?php $id = $_GET['id']; mysql_query($id);")
    assert (flow.sink_type, flow.line) == ("sql", 1)


def test_in_string_variables() -> None:
    php = """<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
$result = mysql_query($query);
"""
    (flow,) = _analyze(php)
    assert (flow.sink_type, flow.source, flow.line) == ("sql", "$_GET", 4)


def test_concatenation() -> None:
    (flow,) = _analyze("<?php $cmd = 'ping ' . $_GET['host']; system($cmd);")
    assert (flow.sink_type, flow.sink_name) == ("command", "system")


def test_concat_assignment() -> None:
    (flow,) = _analyze("<?php $q = 'SELECT '; $q .= $_POST['col']; mysqli_query($conn, $q);")
    assert (flow.sink_type, flow.source) == ("sql", "$_POST")


def test_reassignment_removes_taint() -> None:
    assert _analyze("<?php $x = $_GET['x']; $x = 'safe'; echo $x;") == []


def test_unknown_function_doesnt_sanitize() -> None:
    (flow,) = _analyze("<?php echo strtoupper($_GET['x']);")
    assert flow.sink_type == "xss"


def test_numeric_cast_removes_taint() -> None:
    assert _analyze("<?php $id = (int)$_GET['id']; mysql_query(\"SELECT $id\");") == []


####### sanitizers


def test_sanitizer() -> None:
    assert _analyze("<?php echo htmlspecialchars($_GET['name']);") == []


def test_sanitized_variable_assignment() -> None:
    assert _analyze("<?php $safe = htmlspecialchars($_GET['n']); echo $safe;") == []


def test_sanitizer_removes_only_its_own_sink_type() -> None:
    (flow,) = _analyze("<?php $x = htmlspecialchars($_GET['id']); mysql_query($x);")
    assert flow.sink_type == "sql"


def test_partially_sanitized_concat_stays_tainted() -> None:
    php = "<?php echo htmlspecialchars($_GET['a']) . $_GET['b'];"
    (flow,) = _analyze(php)
    assert flow.sink_type == "xss"


###### sink variants


def test_print_sink() -> None:
    (flow,) = _analyze("<?php print $_COOKIE['token'];")
    assert (flow.sink_type, flow.sink_name) == ("xss", "print")


def test_sql_method_call_sink() -> None:
    (flow,) = _analyze("<?php $pdo->query('SELECT ' . $_GET['q']);")
    assert (flow.sink_type, flow.sink_name) == ("sql", "query")


def test_command_sink() -> None:
    (flow,) = _analyze("<?php $host = $_GET['h']; $out = `ping $host`;")
    assert (flow.sink_type, flow.sink_name) == ("command", "shell_exec")


def test_file_inclusion_sink() -> None:
    (flow,) = _analyze("<?php include($_GET['page']);")
    assert (flow.sink_type, flow.sink_name) == ("file_inclusion", "include")


def test_sink_inside_condition_is_found() -> None:
    (flow,) = _analyze("<?php if (mysql_query($_GET['q'])) { echo 'ok'; }")
    assert flow.sink_type == "sql"


###### scopes


def test_flow_within_function_is_found() -> None:
    php = "<?php function f() { $q = $_POST['x']; system($q); }"
    (flow,) = _analyze(php)
    assert flow.sink_type == "command"


###### traces


def test_trace_records_source_propagation_and_sink() -> None:
    php = """<?php
$id = $_GET['id'];
$query = "SELECT $id";
mysql_query($query);
"""
    (flow,) = _analyze(php)
    lines = [step.line for step in flow.steps]
    descriptions = " | ".join(step.description for step in flow.steps)
    assert lines == [2, 2, 3, 4]
    assert "user input from $_GET" in descriptions
    assert "assigned to $id" in descriptions
    assert "assigned to $query" in descriptions
    assert "reaches sql sink mysql_query" in descriptions


###### model validation


def test_model_rejects_bad_sources() -> None:
    with pytest.raises(ValueError, match="sources"):
        TaintModel.from_dict({"sources": "GET", "sinks": {}, "sanitizers": {}})


def test_model_rejects_non_callable_sink() -> None:
    with pytest.raises(ValueError, match="sink entry"):
        TaintModel.from_dict(
            {"sources": ["$_GET"], "sinks": {"sql": ["not a function"]}, "sanitizers": {}}
        )


def test_model_ignores_descriptive_sanitizer_entries() -> None:
    model = TaintModel.from_dict(
        {
            "sources": ["$_GET"],
            "sinks": {"sql": ["mysql_query"]},
            "sanitizers": {"sql": ["prepared statements (PDO::prepare)"]},
        }
    )
    assert model.sanitizers == {}
