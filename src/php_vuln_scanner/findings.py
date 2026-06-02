from __future__ import annotations

import enum
from dataclasses import dataclass
from php_vuln_scanner.taint_engine import TaintStep

class Severity(enum.StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Rule:
    """A detection rule that includes id, classification, and remediation"""

    rule_id: str  # like "A05-SQLI-001"
    cwe: str | None  # unique CWE identifier if applicable
    severity: Severity
    message: str  # short description of the issue
    remediation: str  # recommendation test, how to fix it

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("rule_id must not be empty")
        if not self.message.strip():
            raise ValueError(f"rule {self.rule_id}: message must not be empty")
        if not self.remediation.strip():
            raise ValueError(f"rule {self.rule_id}: remediation must not be empty")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    module_id: str
    owasp_category: str
    cwe: str | None
    severity: Severity
    file: str  # path relative to scan root
    line: int  # line, counted from 1
    column: int | None
    snippet: str  # snipped of the code
    message: str
    remediation: str
    taint_trace: tuple[TaintStep, ...] | None = None  # for taint findings

    @classmethod
    def from_rule(
        cls,
        rule: Rule,
        *,
        module_id: str,
        owasp_category: str,
        file: str,
        line: int,
        snippet: str,
        column: int | None = None,
        taint_trace: tuple[TaintStep, ...] | None = None,
    ) -> Finding:
        return cls(
            rule_id=rule.rule_id,
            module_id=module_id,
            owasp_category=owasp_category,
            cwe=rule.cwe,
            severity=rule.severity,
            file=file,
            line=line,
            column=column,
            snippet=snippet,
            message=rule.message,
            remediation=rule.remediation,
            taint_trace=taint_trace,
        )

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "module_id": self.module_id,
            "owasp_category": self.owasp_category,
            "cwe": self.cwe,
            "severity": str(self.severity),
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "message": self.message,
            "remediation": self.remediation,
            "taint_trace": (
                [{"line": step.line, "description": step.description} for step in self.taint_trace]
                if self.taint_trace is not None
                else None
            ),
        }
