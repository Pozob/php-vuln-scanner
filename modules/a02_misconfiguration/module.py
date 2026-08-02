from __future__ import annotations

from tree_sitter import Node
from php_vuln_scanner.findings import Rule, Severity, Finding
from php_vuln_scanner.module_api import ModuleContext, ScannerModule
from php_vuln_scanner.file_parser import ParsedFile

RULES: dict[str, Rule] = {
    "debug_output": Rule(
        rule_id="A02-DEBUG-001",
        cwe="CWE-489",
        severity=Severity.LOW,
        message="Debug/error display is enabled in code. It can leaks stack traces, paths, and queries in production",
        remediation=(
            "Disable error display in production with ini_set('display_errors', '0') "
            "and log errors to a file instead of the response."
        ),
    ),
    "insecure_cookie": Rule(
        rule_id="A02-COOKIE-001",
        cwe="CWE-614",
        severity=Severity.MEDIUM,
        message="Cookie is set without the Secure and/or HttpOnly option",
        remediation=(
            "Set cookies with both options: setcookie($name, $value, "
            "[..., 'secure' => true, 'httponly' => true, 'samesite' => 'Lax'])"
        ),
    ),
    "insecure_session": Rule(
        rule_id="A02-SESSION-001",
        cwe="CWE-614",
        severity=Severity.MEDIUM,
        message="Session cookie protection is weakened",
        remediation=(
            "Configure sessions with session_set_cookie_params(['secure' => true, "
            "'httponly' => true, 'samesite' => 'Lax']) before session_start(). If "
            "using older PHP Versions an not bein able to upgrade, use the old"
            "signature of session_set_cookie_params() with secure = true, domain set "
            "and httponly = true."
        ),
    ),
    "wildcard_cors": Rule(
        rule_id="A02-CORS-001",
        cwe="CWE-942",
        severity=Severity.MEDIUM,
        message="The origin of CORS is configure with a wildcard (*)",
        remediation=(
            "Replace the wildcard with an allowlist of trusted origins"
        ),
    ),
    "tls_verification_disabled": Rule(
        rule_id="A02-TLS-001",
        cwe="CWE-295",
        severity=Severity.HIGH,
        message="TLS certificate verification is disabled, enabling MITM attacks",
        remediation=(
            "Keep CURLOPT_SSL_VERIFYPEER=true and CURLOPT_SSL_VERIFYHOST=2"
        ),
    ),
    "dangerous_ini": Rule(
        rule_id="A02-INI-001",
        cwe="CWE-829",
        severity=Severity.HIGH,
        message="A dangerous PHP setting is enabled at runtime (allow_url_include/register_globals)",
        remediation=(
            "Dont enable allow_url_include or register_globals. Load from local "
            "file instead and access variables from sources like $_GET & $_POST"
        ),
    ),
}

# Every check in this module hangs off a plain function call written with a literal name.
_CALLS_QUERY = "(function_call_expression function: (name) @fn) @call"

# Position of the parameters counted from 0
_COOKIE_PARAM_POSITIONS = {
    "setcookie": {
        # 7.3 Signature
        "OPTIONS": 2,
        # Pre 7.3
        "SECURE": 5,
        "HTTPONLY": 6,
    },
    "session_set_cookie_params": {
        # 7.3 Signature
        "OPTIONS": 0,
        # Pre 7.3
        "SECURE": 3,
        "HTTPONLY": 4,
    }
}


def _cfg_list(config: dict, key: str) -> list[str]:
    value = config.get(key)

    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"a02_misconfiguration config '{key}' must be a list of strings")
    return value


def _call_args(call: Node) -> list[Node]:
    """Return the argument expressions of a call, unwrapped from their "argument" nodes"""
    arguments = call.child_by_field_name("arguments")
    args = arguments.named_children if arguments is not None else []

    return [a.named_children[0] for a in args if a.type == "argument" and a.named_children]

def _string_content(parsed_file: ParsedFile, node: Node) -> str:
    """Returns the literal text of a string node, without the surrounding quotes

    Only literal parts are collected. In an interpolated string the embedded expressions are skipped,
    so header("Access-Control-Allow-Origin: $origin") just returns the static part
    """
    return "".join(
        parsed_file.text(child) for child in node.named_children if child.type in ("string_content", "escape_sequence")
    )


class A02MisconfigurationModule(ScannerModule):
    def rules(self) -> list[Rule]:
        return list(RULES.values())

    def analyze(self, parsed_files: list[ParsedFile], context: ModuleContext) -> list[Finding]:
        # get the config
        cfg = context.config

        self._debug_flags = set(_cfg_list(cfg, "debug_ini_flags"))
        self._debug_reporting = set(_cfg_list(cfg, "debug_error_reporting_constants"))
        self._session_flags = set(_cfg_list(cfg, "session_hardening_ini_flags"))
        self._dangerous_flags = set(_cfg_list(cfg, "dangerous_ini_enable_flags"))
        self._tls_options = set(_cfg_list(cfg, "tls_verify_options"))
        self._truthy_values = set(_cfg_list(cfg, "truthy_values"))
        self._falsy_values = set(_cfg_list(cfg, "falsy_values"))

        findings: list[Finding] = []
        for parsed_file in parsed_files:
            for match in context.parsing.matches(parsed_file.root, _CALLS_QUERY):
                call = match["call"][0]
                name = parsed_file.text(match["fn"][0])

                rule_key = self._check_call(parsed_file, name, call)
                if rule_key is not None:
                    findings.append(self._create_finding(rule_key, parsed_file, context, call))
        return findings

    def _check_call(self, parsed_file: ParsedFile, name: str, call: Node) -> str | None:
        """Dispatch one call to its check and return the rule key it violates, if any"""
        args = _call_args(call)

        if name == "ini_set":
            return self._check_ini_set(parsed_file, args)
        if name == "error_reporting":
            if args and parsed_file.text(args[0]) in self._debug_reporting:
                return "debug_output"
        elif name == "setcookie":
            if self._cookie_options_missing(parsed_file, args,
                                            secure_param_pos=_COOKIE_PARAM_POSITIONS[name]["SECURE"],
                                            httponly_param_pos=_COOKIE_PARAM_POSITIONS[name]["HTTPONLY"],
                                            options_param_pos=_COOKIE_PARAM_POSITIONS[name]["OPTIONS"]):
                return "insecure_cookie"
        elif name == "session_set_cookie_params":
            if self._cookie_options_missing(parsed_file, args, secure_param_pos=_COOKIE_PARAM_POSITIONS[name]["SECURE"],
                                            httponly_param_pos=_COOKIE_PARAM_POSITIONS[name]["HTTPONLY"],
                                            options_param_pos=_COOKIE_PARAM_POSITIONS[name]["OPTIONS"]):
                return "insecure_session"
        elif name == "header":
            if args and self._is_wildcard_cors(parsed_file, args[0]):
                return "wildcard_cors"
        elif name == "curl_setopt":
            # curl_setopt($ch, OPTION, $value): the option is a constant,
            # so its raw source text is compared against the configured names.
            if len(args) >= 3 and parsed_file.text(args[1]) in self._tls_options and self._is_falsy(parsed_file, args[2]):
                return "tls_verification_disabled"
        elif name == "curl_setopt_array":
            if len(args) >= 2 and self._array_disables_tls(parsed_file, args[1]):
                return "tls_verification_disabled"
        return None

    def _check_ini_set(self, pased_file: ParsedFile, args: list[Node]) -> str | None:
        """Map an ini_set() call to a rule based on its key and whether the value enables or disables it

        We need to differenciate between debug and dangerous flags which shlould be off and ession hardening flags
        which should be on
        """
        # A non literal key cannot be resolved, so the call is skipped instead of guessed.
        if len(args) < 2 or args[0].type != "string":
            return None

        key = _string_content(pased_file, args[0])
        if key in self._debug_flags and self._is_truthy(pased_file, args[1]):
            return "debug_output"
        if key in self._session_flags and self._is_falsy(pased_file, args[1]):
            return "insecure_session"
        if key in self._dangerous_flags and self._is_truthy(pased_file, args[1]):
            return "dangerous_ini"
        return None

    def _cookie_options_missing(
        self, parsed_file: ParsedFile, args: list[Node], *, secure_param_pos: int, httponly_param_pos: int, options_param_pos: int
    ) -> bool:
        """Checks if secure or httponly is not set to true

        Which of the two signatures is in use is decided by the node type at the options position.
        If a literal array ist used, it can ony be the 7.3+ form.
        Anything else (most importantly a variable holding the options) fallsback to the old signature check
        """
        # Modern Signature
        if len(args) > options_param_pos and args[options_param_pos].type == "array_creation_expression":
            options = self._extract_bools_from_array(parsed_file, args[options_param_pos])
            # "is True" and not truthiness: a missing key and a non literal value
            # both come back as None and must count as not proven safe.
            return not (options.get("secure") is True and options.get("httponly") is True)

        # Old Signature: both flags default to false, so an argument that is not
        # passed at all is just as insecure as one explicitly passed as false.
        missing = False
        for position in (secure_param_pos, httponly_param_pos):
            if len(args) <= position:
                missing = True  # option not passed, PHP defaults to off
            elif args[position].type == "boolean" and parsed_file.text(args[position]).lower() == "false":
                missing = True
        return missing

    def _is_wildcard_cors(self, parsed_file: ParsedFile, arg: Node) -> bool:
        """Detects header("Access-Control-Allow-Origin: *")

        header() serves every HTTP header, so the header name has to be matched first to avoid reporting
        an unrelated header that happens to contain a star
        """
        if arg.type not in ("string", "encapsed_string"):
            return False

        value = _string_content(parsed_file, arg).lower()
        return value.startswith("access-control-allow-origin") and "*" in value

    def _array_disables_tls(self, parsed_file: ParsedFile, array: Node) -> bool:
        if array.type != "array_creation_expression":
            return False

        flags = self._extract_bools_from_array(parsed_file, array)
        # Only a literal false counts as disabled here. Unlike the cookie check an unknown value is not reported,
        # because leaving the option out of the array keeps curl's secure default.
        return any(key in self._tls_options and value is False for key, value in flags.items())

    def _is_truthy(self, parsed_file: ParsedFile, node: Node) -> bool:
        """Checks if the value is truthy"""
        return self._get_value(parsed_file, node) in self._truthy_values

    def _is_falsy(self, parsed_file: ParsedFile, node: Node) -> bool:
        """Checks if the value is falsy"""
        return self._get_value(parsed_file, node) in self._falsy_values

    def _get_value(self, psared_file: ParsedFile, node: Node) -> str | None:
        """Normalize a literal to a lowercase string, or None if it is not a literal

        PHP accepts ini values in several versions ("1", "On", true),
        which is why the comparison happens against the truthy/falsy lists from the config
        instead of directly against a single value. None means the value could
        not be determined and therefore matches neither list.
        """
        if node.type == "string":
            return _string_content(psared_file, node).lower()

        if node.type in ("integer", "boolean"):
            return psared_file.text(node).lower()

        return None

    def _extract_bools_from_array(self, parsed_fiel: ParsedFile, array: Node) -> dict[str, bool | None]:
        """Checks a array for boolean values and returns a dict matching the keys to boolean values or None.

        A key is mapped to None when its value is not a boolean
        """
        result: dict[str, bool | None] = {}

        for element in array.named_children:
            if element.type != "array_element_initializer" or len(element.named_children) < 2:
                continue

            key_node, value_node = element.named_children[0], element.named_children[1]
            # Quotes are removes from Strings, everything else keeps its raw form
            # so constants like CURLOPT_SSL_VERIFYPEER stay comparable to
            # the names configured in config.yaml.
            key = _string_content(parsed_fiel, key_node) if key_node.type == "string" else parsed_fiel.text(key_node)

            if value_node.type == "boolean":
                result[key] = parsed_fiel.text(value_node).lower() == "true"
            else:
                result[key] = None

        return result


    def _create_finding(self, rule_key: str, pf: ParsedFile, context: ModuleContext, node: Node) -> Finding:
        return Finding.from_rule(
            RULES[rule_key],
            module_id=context.module_id,
            owasp_category=context.owasp_category,
            file=pf.rel_path,
            line=pf.line(node),
            column=pf.column(node),
            snippet=pf.snippet(node),
        )
