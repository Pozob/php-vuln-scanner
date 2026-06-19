from __future__ import annotations

from pathlib import Path

import pytest

from php_vuln_scanner.module_loader import discover_modules
from php_vuln_scanner.module_api import ModuleContext
from php_vuln_scanner.file_parser import ParsingService
from php_vuln_scanner.findings import Finding

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def a02():
    modules = discover_modules(REPO_ROOT / "modules", REPO_ROOT / "no-config-overrides")
    return next(m for m in modules if m.manifest.id == "a02_misconfiguration")


def _findings_in(a02, php: str, config: dict | None = None) -> list[Finding]:
    parsing = ParsingService()
    parsed = parsing.parse_source(php.encode(), Path("test.php"), "test.php")
    context = ModuleContext(
        module_id=a02.manifest.id,
        owasp_category=a02.manifest.owasp_category,
        config=config if config is not None else a02.config,
        parsing=parsing,
    )
    return a02.instance.analyze([parsed], context)


def _rule_ids(a02, php: str) -> list[str]:
    return [f.rule_id for f in _findings_in(a02, php)]


def test_display_errors(a02) -> None:
    assert _rule_ids(a02, "<?php ini_set('display_errors', '1');") == ["A02-DEBUG-001"]
    assert _rule_ids(a02, "<?php ini_set('display_startup_errors', 'On');") == ["A02-DEBUG-001"]


def test_display_errors_disabled_is_clean(a02) -> None:
    assert _rule_ids(a02, "<?php ini_set('display_errors', '0');") == []


def test_error_reporting(a02) -> None:
    assert _rule_ids(a02, "<?php error_reporting(E_ALL);") == ["A02-DEBUG-001"]
    assert _rule_ids(a02, "<?php error_reporting(0);") == []


def test_allow_url_include(a02) -> None:
    assert _rule_ids(a02, "<?php ini_set('allow_url_include', '1');") == ["A02-INI-001"]
    assert _rule_ids(a02, "<?php ini_set('allow_url_include', '0');") == []


def test_ini_set_with_variable_is_not_guessed(a02) -> None:
    assert _rule_ids(a02, "<?php ini_set('display_errors', $level);") == []


def test_setcookie_without_flags(a02) -> None:
    assert _rule_ids(a02, "<?php setcookie('auth', $t, time() + 3600);") == ["A02-COOKIE-001"]


def test_setcookie_positional_flags_ok(a02) -> None:
    assert _rule_ids(a02, "<?php setcookie('a', $t, 0, '/', '', true, true);") == []


def test_setcookie_httponly(a02) -> None:
    assert _rule_ids(a02, "<?php setcookie('a', $t, 0, '/', '', true, false);") == ["A02-COOKIE-001"]


def test_setcookie_options_array(a02) -> None:
    ok = "<?php setcookie('a', $t, ['secure' => true, 'httponly' => true]);"
    missing = "<?php setcookie('a', $t, ['secure' => true]);"
    assert _rule_ids(a02, ok) == []
    assert _rule_ids(a02, missing) == ["A02-COOKIE-001"]


def test_setcookie_dynamic_flags_not_guessed(a02) -> None:
    assert _rule_ids(a02, "<?php setcookie('a', $t, 0, '/', '', $secure, $httponly);") == []


def test_session_cookie_params(a02) -> None:
    ok = "<?php session_set_cookie_params(['secure' => true, 'httponly' => true]);"
    missing = "<?php session_set_cookie_params(['lifetime' => 3600]);"
    assert _rule_ids(a02, ok) == []
    assert _rule_ids(a02, missing) == ["A02-SESSION-001"]


def test_session_ini_settings(a02) -> None:
    assert _rule_ids(a02, "<?php ini_set('session.cookie_httponly', '0');") == ["A02-SESSION-001"]
    assert _rule_ids(a02, "<?php ini_set('session.cookie_secure', '1');") == []


def test_wildcard_cors(a02) -> None:
    assert _rule_ids(a02, "<?php header('Access-Control-Allow-Origin: *');") == ["A02-CORS-001"]


def test_specific_origin_and_other_headers_are_allowed(a02) -> None:
    assert _rule_ids(a02, "<?php header('Access-Control-Allow-Origin: https://a.example');") == []
    assert _rule_ids(a02, "<?php header('Content-Type: text/html');") == []


def test_tls_verification_disabled(a02) -> None:
    assert _rule_ids(a02, "<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);") == ["A02-TLS-001"]
    assert _rule_ids(a02, "<?php curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);") == ["A02-TLS-001"]


def test_tls_verification_enabled_is_clean(a02) -> None:
    assert _rule_ids(a02, "<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);") == []
    assert _rule_ids(a02, "<?php curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);") == []


def test_curl_setopt_array_form(a02) -> None:
    assert _rule_ids(a02, "<?php curl_setopt_array($ch, [CURLOPT_SSL_VERIFYPEER => false]);") == ["A02-TLS-001"]
