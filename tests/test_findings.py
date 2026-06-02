from __future__ import annotations

import pytest
from php_vuln_scanner.findings import Finding, Rule, Severity


def _make_rule(**overrides) -> Rule:
    defaults = dict(
        rule_id="T-001",
        cwe="CWE-999",
        severity=Severity.HIGH,
        message="Test issue.",
        remediation="Just testing it",
    )
    return Rule(**{**defaults, **overrides})


def test_rule_without_remediation_is_not_allowed() -> None:
    with pytest.raises(ValueError, match="remediation"):
        _make_rule(remediation="")
    with pytest.raises(ValueError, match="remediation"):
        _make_rule(remediation="   ")


def test_rule_requires_id_and_message() -> None:
    with pytest.raises(ValueError, match="rule_id"):
        _make_rule(rule_id="")
    with pytest.raises(ValueError, match="message"):
        _make_rule(message="")


def test_finding_inherits_rule_fields() -> None:
    finding = Finding.from_rule(
        _make_rule(),
        module_id="test_module",
        owasp_category="A05:2025",
        file="a.php",
        line=3,
        snippet="echo $x;",
    )
    assert finding.rule_id == "T-001"
    assert finding.remediation == "Just testing it"
    assert finding.cwe == "CWE-999"


def test_finding_to_dict() -> None:
    finding = Finding.from_rule(
        _make_rule(),
        module_id="test_module",
        owasp_category="A05:2025",
        file="a.php",
        line=3,
        snippet="echo $x;",
    )
    data = finding.to_dict()
    assert data["severity"] == "high"
    assert data["taint_trace"] is None
    assert set(data) == {
        "rule_id", "module_id", "owasp_category", "cwe", "severity",
        "file", "line", "column", "snippet", "message", "remediation", "taint_trace",
    }
