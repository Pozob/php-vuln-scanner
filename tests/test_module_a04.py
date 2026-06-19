from __future__ import annotations

from pathlib import Path

import pytest

from php_vuln_scanner.findings import Finding
from php_vuln_scanner.module_api import ModuleContext
from php_vuln_scanner.module_loader import discover_modules
from php_vuln_scanner.file_parser import ParsingService

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def a04():
    modules = discover_modules(REPO_ROOT / "modules", REPO_ROOT / "use-default-config")
    return next(m for m in modules if m.manifest.id == "a04_crypto_failures")


def _findings_in(a04, php: str, config: dict | None = None) -> list[Finding]:
    parsing = ParsingService()
    parsed = parsing.parse_source(php.encode(), Path("temp.php"), "temp.php")
    context = ModuleContext(
        module_id=a04.manifest.id,
        owasp_category=a04.manifest.owasp_category,
        config=config if config is not None else a04.config,
        parsing=parsing,
    )
    return a04.instance.analyze([parsed], context)


def _rule_ids(a04, php: str) -> list[str]:
    return [f.rule_id for f in _findings_in(a04, php)]


# region hashing

def test_md5_in_password_context_is_credential_hashing(a04) -> None:
    assert _rule_ids(a04, "<?php $hash = md5($password);") == ["A04-HASH-001"]


def test_md5_without_password_context_is_general_weak_hash(a04) -> None:
    assert _rule_ids(a04, "<?php $checksum = md5($file_contents);") == ["A04-HASH-002"]


def test_sha1_comparison_near_password_identifier(a04) -> None:
    assert _rule_ids(a04, "<?php if (sha1($input) === $stored_password_hash) { $ok = true; }") == ["A04-HASH-001"]


def test_crypt_without_salt_is_flagged(a04) -> None:
    assert _rule_ids(a04, "<?php $h = crypt($pw);") == ["A04-HASH-001"]


def test_crypt_with_weak_literal_salt_is_flagged(a04) -> None:
    assert _rule_ids(a04, "<?php $h = crypt($pw, '$1$abc$');") == ["A04-HASH-001"]


def test_crypt_with_strong_salt_is_clean(a04) -> None:
    assert _rule_ids(a04, "<?php $h = crypt($pw, '$2y$10$abcdefghijklmnopqrstuv');") == []


def test_crypt_with_dynamic_salt_is_not_guessed(a04) -> None:
    assert _rule_ids(a04, "<?php $h = crypt($pw, $salt);") == []


def test_password_hash_is_clean(a04) -> None:
    assert _rule_ids(a04, "<?php $h = password_hash($password, PASSWORD_DEFAULT);") == []

# endregion
# region randmoness

def test_insecure_random_functions_flagged(a04) -> None:
    assert _rule_ids(a04, "<?php $t = uniqid(rand(), true);") == ["A04-RAND-001"] * 2


def test_random_bytes_and_int_is_clean(a04) -> None:
    assert _rule_ids(a04, "<?php $t = bin2hex(random_bytes(32)); $n = random_int(0, 9);") == []

# endregion
# region ciphers & openssl

def test_mcrypt_is_deprecated(a04) -> None:
    php = "<?php $c = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_ECB);"
    assert _rule_ids(a04, php) == ["A04-CRYPTO-001"]


def test_openssl_with_weak_cipher_flagged(a04) -> None:
    assert _rule_ids(a04, "<?php $c = openssl_encrypt($data, 'DES-ECB', $key);") == ["A04-CRYPTO-002"]
    assert _rule_ids(a04, "<?php $c = openssl_encrypt($data, 'aes-128-ecb', $key);") == ["A04-CRYPTO-002"]


def test_openssl_with_aead_cipher_clean(a04) -> None:
    assert _rule_ids(a04, "<?php $c = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);") == []

# endregion
# region hardcoded secrets

def test_secret_in_array_key_and_define_flagged(a04) -> None:
    php = "<?php $config['api_key'] = 'sk_live_123456'; define('SECRET_TOKEN', 'tok_9f8e');"
    assert _rule_ids(a04, php) == ["A04-SECRET-001"] * 2


def test_non_literal_or_short_values_clean(a04) -> None:
    assert _rule_ids(a04, "<?php $password = $_POST['password'];") == []
    assert _rule_ids(a04, "<?php $token = \"prefix_$id\";") == []
    assert _rule_ids(a04, "<?php $password = '';") == []


def test_unrelated_assignment_clean(a04) -> None:
    assert _rule_ids(a04, "<?php $greeting = 'hello world';") == []

# endregion


def test_missing_config_key_raises(a04) -> None:
    with pytest.raises(ValueError, match="weak_hash_functions"):
        _findings_in(a04, "<?php $x = 1;", config={})
