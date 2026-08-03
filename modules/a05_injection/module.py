from __future__ import annotations

import logging
from php_vuln_scanner.findings import Rule, Severity, Finding
from php_vuln_scanner.module_api import ModuleContext, ScannerModule
from php_vuln_scanner.file_parser import ParsedFile

logger = logging.getLogger(__name__)

RULES_BY_SINK_TYPE: dict[str, Rule] = {
    "sql": Rule(
        rule_id="A05-SQLI-001",
        cwe="CWE-89",
        severity=Severity.HIGH,
        message="User input reaches an SQL query sink without SQL sanitization (SQL injection).",
        remediation=(
            "Use prepared statements with bound parameters (PDO::prepare with "
            "placeholders, or mysqli_prepare/bind_param) instead of building the "
            "query string from user input. If a legacy API forces string building, "
            "escape values with mysqli_real_escape_string and quote them"
        ),
    ),
    "xss": Rule(
        rule_id="A05-XSS-001",
        cwe="CWE-79",
        severity=Severity.MEDIUM,
        message="User input is written to the HTML without output encoding (cross-site scripting).",
        remediation=(
            "Encode user controlled data before output: "
            "htmlspecialchars($value, ENT_QUOTES)."
        ),
    ),
    "command": Rule(
        rule_id="A05-CMD-001",
        cwe="CWE-78",
        severity=Severity.HIGH,
        message="User input reaches an OS command execution sink (command injection).",
        remediation=(
            "Do not pass user input to shell commands. If unavoidable, wrap each "
            "argument in escapeshellarg() and validate it against a strict "
            "allowlist, however it is prefered to use PHP-native APIs over using the shell"
        ),
    ),
    "code": Rule(
        rule_id="A05-CODE-001",
        cwe="CWE-95",
        severity=Severity.HIGH,
        message="User input reaches eval()/assert() (code injection).",
        remediation=(
            "Never pass user input to eval() or assert(). Replace dynamic code "
            "evaluation with explicit control flow"
        ),
    ),
    "file_inclusion": Rule(
        rule_id="A05-FILE-001",
        cwe="CWE-98",
        severity=Severity.HIGH,
        message="User input controls the path of an include/require (file inclusion).",
        remediation=(
            "Dont build include paths from user input. Map user-supplied names"
            "to files via a fixed allowlist array, and pin includes to a fixed,"
            "constant base directory."
        ),
    ),
}

# Unlike the pattern based modules this one owns no detection logic of its own
# the taint engine finds the flows and this module only turns them into findings
class A05InjectionModule(ScannerModule):
    def rules(self) -> list[Rule]:
        return list(RULES_BY_SINK_TYPE.values())

    def analyze(self, parsed_files: list[ParsedFile], context: ModuleContext) -> list[Finding]:
        # Sources, sinks and sanitizers all come from the module config, so the
        # engine is built per run and only knows what the config declares
        engine = context.create_taint_engine(context.config["taint_model"])
        findings: list[Finding] = []

        for parsed_file in parsed_files:
            for flow in engine.analyze_file(parsed_file):
                # The config can declare a sink type this module has no rule
                # for. That is a configuration mistake, so the taint flow is
                # logged and dropped instead of raising
                rule = RULES_BY_SINK_TYPE.get(flow.sink_type)
                if rule is None:
                    logger.warning(
                        "a05_injection: no rule for configured sink type %r. Flow at %s:%d ignored",
                        flow.sink_type, parsed_file.rel_path, flow.line,
                    )
                    continue
                findings.append(
                    Finding.from_rule(
                        rule,
                        module_id=context.module_id,
                        owasp_category=context.owasp_category,
                        file=parsed_file.rel_path,
                        line=flow.line,
                        column=flow.sink_node.start_point[1] + 1,
                        snippet=parsed_file.snippet(flow.sink_node),
                        taint_trace=flow.steps, # The step trace is what makes the finding stiches the flow togetger.
                    )
                )
        return findings
