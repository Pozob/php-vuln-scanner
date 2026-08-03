from __future__ import annotations

import re

from tree_sitter import Node
from php_vuln_scanner.findings import Rule, Severity, Finding
from php_vuln_scanner.module_api import ModuleContext, ScannerModule
from php_vuln_scanner.file_parser import ParsedFile

RULES: dict[str, Rule] = {
    "password_hash": Rule(
        rule_id="A04-HASH-001",
        cwe="CWE-916",
        severity=Severity.HIGH,
        message="A weak password hash algorithm is used (md5/sha1/DES-crypt are brute-forceable).",
        remediation=(
            "Hash passwords with password_hash($password, PASSWORD_DEFAULT) and "
            "check them with password_verify(). Never use md5(), sha1(), or "
            "crypt() with weak salts for credentials. Check for rehashing with"
            "password_needs_rehash() and rehash on next login "
        ),
    ),
    "weak_hash": Rule(
        rule_id="A04-HASH-002",
        cwe="CWE-328",
        severity=Severity.MEDIUM,
        message="Use of a cryptographically broken hash function (md5/sha1).",
        remediation=(
            "Use hash('sha256', ...) or stronger for integrity checks. If the "
            "value protects passwords, use password_hash() instead."
        ),
    ),
    "insecure_random": Rule(
        rule_id="A04-RAND-001",
        cwe="CWE-338",
        severity=Severity.MEDIUM,
        message="Insecure random source (rand/mt_rand/uniqid). It can be predictable.",
        remediation=(
            "Use random_bytes() or random_int() for tokens, session, ids, "
            "reset links, and any other security-relevant randomness."
        ),
    ),
    "deprecated_api": Rule(
        rule_id="A04-CRYPTO-001",
        cwe="CWE-327",
        severity=Severity.MEDIUM,
        message="Use of the deprecated mcrypt API (removed in PHP 7.2).",
        remediation=(
            "Replace mcrypt_* with sodium_crypto_secretbox() (libsodium) or "
            "openssl_encrypt() using an AEAD cipher such as aes-256-gcm."
        ),
    ),
    "weak_cipher": Rule(
        rule_id="A04-CRYPTO-002",
        cwe="CWE-327",
        severity=Severity.HIGH,
        message="Broken cipher or mode (DES/RC4/ECB) used in an openssl_* call.",
        remediation=(
            "Use an authenticated cipher: openssl_encrypt(..., 'aes-256-gcm', ...) "
            "with a random IV per message, or libsodium. Never use DES/RC4, and "
            "never ECB mode."
        ),
    ),
    "hardcoded_secret": Rule(
        rule_id="A04-SECRET-001",
        cwe="CWE-798",
        severity=Severity.MEDIUM,
        message="Possible hardcoded secret: a string literal is assigned to a credential-like name.",
        remediation=(
            "Load secrets from the environment (getenv) or a secrets manager, "
            "keep them out of version control, and rotate out any secret that "
            "was committed."
        ),
    ),
}

_CALLS_QUERY = "(function_call_expression function: (name) @fn) @call"

_ASSIGN_QUERY = (
    "(assignment_expression"
    " left: [(variable_name) (subscript_expression)] @left"
    " right: [(string) (encapsed_string)] @value) @assign"
)

# Splits a cipher string into its parts, so "aes-256-ecb" becomes the tokens
# aes, 256 and ecb. We do this, because comparing whole tokens instead of substrings
# prevents a match on an unrelated string that just contains a substring of it.
_TOKEN_REGEX = re.compile(r"[^a-z0-9]+")


def _cfg_list(config: dict, key: str) -> list[str]:
    value = config.get(key)

    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"a04_crypto_failures config: '{key}' must be a list of strings")

    return value


def _string_content(parsed_file: ParsedFile, node: Node) -> str:
    """Returns the text of a string node"""
    return "".join(
        parsed_file.text(child) for child in node.named_children if child.type in ("string_content", "escape_sequence")
    )


def _contains_variable(node: Node) -> bool:
    """True if an interpolated string embeds a variable somewhere

    Used to tell a real literal apart from a string that is only partly static:
    "secret_$env" is built at runtime and is neither a hardcoded secret nor a salt
    """
    if node.type == "variable_name":
        return True

    return any(_contains_variable(child) for child in node.named_children)


def _call_args(call: Node) -> list[Node]:
    """Return the argument expressions of a call, unwrapped from their "argument" nodes"""
    arguments = call.child_by_field_name("arguments")
    args = arguments.named_children if arguments is not None else []

    return [a.named_children[0] for a in args if a.type == "argument" and a.named_children]


class A04CryptoFailuresModule(ScannerModule):
    def rules(self) -> list[Rule]:
        return list(RULES.values())

    def analyze(self, parsed_files: list[ParsedFile], context: ModuleContext) -> list[Finding]:
        # load the config
        cfg = context.config

        self._weak_hashes = set(_cfg_list(cfg, "weak_hash_functions"))
        self._password_words = [w.lower() for w in _cfg_list(cfg, "password_context_identifiers")]
        self._insecure_random = set(_cfg_list(cfg, "insecure_random_functions"))
        self._deprecated_prefixes = tuple(_cfg_list(cfg, "deprecated_crypto_prefixes"))
        self._weak_cipher_tokens = {t.lower() for t in _cfg_list(cfg, "weak_cipher_indicators")}
        self._strong_salts = tuple(_cfg_list(cfg, "strong_crypt_salt_prefixes"))
        self._secret_words = [w.lower() for w in _cfg_list(cfg, "secret_variable_identifiers")]
        self._min_secret_length = int(cfg.get("min_secret_length", 4))

        findings: list[Finding] = []
        for parsed_file in parsed_files:
            self._check_calls(parsed_file, context, findings)
            self._check_assigned_secrets(parsed_file, context, findings)
        return findings

    # region fucntion call checks

    def _check_calls(self, parsed_file: ParsedFile, context: ModuleContext, findings: list[Finding]) -> None:
        """Check every call against the crypto rules

        A call can only violate one of the rules
        """
        for match in context.parsing.matches(parsed_file.root, _CALLS_QUERY):
            call, fn = match["call"][0], match["fn"][0]
            name = parsed_file.text(fn)

            if name in self._weak_hashes:
                # We always report a unsafe hash, but hashing credentials
                # with it is a more severe finding, so the two cases get different rules.
                key = "password_hash" if self._in_password_context(parsed_file, call) else "weak_hash"
                findings.append(self._finding(key, parsed_file, context, call))
            elif name == "crypt" and self._crypt_salt_is_weak(parsed_file, call):
                findings.append(self._finding("password_hash", parsed_file, context, call))
            elif name in self._insecure_random:
                findings.append(self._finding("insecure_random", parsed_file, context, call))
            elif name.startswith(self._deprecated_prefixes):
                findings.append(self._finding("deprecated_api", parsed_file, context, call))
            elif name.startswith("openssl_") and self._uses_weak_cipher(parsed_file, call):
                findings.append(self._finding("weak_cipher", parsed_file, context, call))
            elif name == "define":
                self._check_define_secret(parsed_file, context, call, findings)

    def _in_password_context(self, parsed_file: ParsedFile, call: Node) -> bool:
        """Guesses whether a hash call operates on a credential

        Whether a value is a password cannot be decided from the AST,
        so this falls back to the wording of the source line the call sits on
        (md5($password), $row['passwd'], ...).
        It is only a guess, so it misses credentials stored under an unrelated name,
        and it triggers on any line that just mentions one of the configured words
        """
        line = parsed_file.snippet(call).lower()
        return any(word in line for word in self._password_words)

    def _crypt_salt_is_weak(self, pf: ParsedFile, call: Node) -> bool:
        """Checks if the password salt is weak or insecure as per config"""
        args = _call_args(call)

        if len(args) < 2:
            return True  # no salt at all, PHP falls back to the weakest algorithm

        # A salt that is computed at runtime cannot be judged here
        # It is left alone rather than reported,
        # so a correct dynamic salt does not become a false positive
        salt = args[1]
        if salt.type not in ("string", "encapsed_string") or _contains_variable(salt):
            return False

        return not _string_content(pf, salt).startswith(self._strong_salts)

    def _uses_weak_cipher(self, parsed_file: ParsedFile, call: Node) -> bool:
        """Checks if a weak cipher is used

        The cipher sits at a different position in every openssl_* function,
        so instead of relying on positions for every function,
        every string argument is checked for a broken cipher or mode.
        """
        for arg in _call_args(call):
            if arg.type in ("string", "encapsed_string"):
                tokens = set(_TOKEN_REGEX.split(_string_content(parsed_file, arg).lower()))
                if tokens & self._weak_cipher_tokens:
                    return True
        return False

    def _check_define_secret(
        self, parsed_file: ParsedFile, context: ModuleContext, call: Node, findings: list[Finding]
    ) -> None:
        """Checks if there may be a secret assigned through define (define('DB_PASSWORD', '...'))"""
        args = _call_args(call)

        if len(args) < 2 or args[0].type != "string" or args[1].type not in ("string", "encapsed_string"):
            return

        name = _string_content(parsed_file, args[0]).lower()
        if any(word in name for word in self._secret_words) and not _contains_variable(args[1]):
            # We check a min length for secrets, so placeholders are not reported
            if len(_string_content(parsed_file, args[1])) >= self._min_secret_length:
                findings.append(self._finding("hardcoded_secret", parsed_file, context, call))

    # endregion

    def _check_assigned_secrets(
        self, parsed_file: ParsedFile, context: ModuleContext, findings: list[Finding]
    ) -> None:
        """Checks if there may be a secret assigned

        A string literal is not suspicious on its own,
        so the decision is made by the name it is assigned to.
        This makes this the most uncertain check in the module:
        it only sees names, not what the value is used for
        """
        for match in context.parsing.matches(parsed_file.root, _ASSIGN_QUERY):
            assign, left, value = match["assign"][0], match["left"][0], match["value"][0]
            name = parsed_file.text(left).lower()

            if not any(word in name for word in self._secret_words):
                continue
            if _contains_variable(value):
                continue  # "...$var..." is not a literal secret
            if len(_string_content(parsed_file, value)) < self._min_secret_length:
                continue # to short for a secret
            findings.append(self._finding("hardcoded_secret", parsed_file, context, assign))

    def _finding(self, rule_key: str, parsed_file: ParsedFile, context: ModuleContext, node: Node) -> Finding:
        return Finding.from_rule(
            RULES[rule_key],
            module_id=context.module_id,
            owasp_category=context.owasp_category,
            file=parsed_file.rel_path,
            line=parsed_file.line(node),
            column=parsed_file.column(node),
            snippet=parsed_file.snippet(node),
        )
