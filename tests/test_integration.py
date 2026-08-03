from __future__ import annotations

from pathlib import Path
import yaml

from php_vuln_scanner.cli import EXIT_CLEAN, EXIT_FINDINGS, main, EXIT_ERROR
from php_vuln_scanner.scanner import run_scan

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
MODULES_DIR = REPO_ROOT / "modules"

# file, rule, line
EXPECTED_FINDINGS = {
    # A05
    ("sqli_legacy.php", "A05-SQLI-001", 5),
    ("xss_reflected.php", "A05-XSS-001", 4),
    ("cmd_injection.php", "A05-CMD-001", 4),
    ("include_eval.php", "A05-FILE-001", 4),
    ("include_eval.php", "A05-CODE-001", 5),
    ("file_upload.php", "A05-SQLI-001", 4),
    # A04
    ("weak_hash.php", "A04-HASH-001", 3),
    ("weak_hash.php", "A04-HASH-001", 5),
    ("weak_hash.php", "A04-HASH-001", 6),
    ("insecure_random.php", "A04-RAND-001", 3),
    ("deprecated_crypto.php", "A04-CRYPTO-001", 3),
    ("deprecated_crypto.php", "A04-CRYPTO-002", 4),
    ("hardcoded_secrets.php", "A04-SECRET-001", 3),
    ("hardcoded_secrets.php", "A04-SECRET-001", 4),
    ("hardcoded_secrets.php", "A04-SECRET-001", 5),
    # A02
    ("insecure_random.php", "A02-COOKIE-001", 4),
    ("debug_toggles.php", "A02-DEBUG-001", 3),
    ("debug_toggles.php", "A02-DEBUG-001", 4),
    ("debug_toggles.php", "A02-INI-001", 5),
    ("insecure_cookies.php", "A02-COOKIE-001", 3),
    ("insecure_cookies.php", "A02-SESSION-001", 4),
    ("insecure_cookies.php", "A02-SESSION-001", 5),
    ("cors_tls.php", "A02-CORS-001", 3),
    ("cors_tls.php", "A02-TLS-001", 5),
    ("cors_tls.php", "A02-TLS-001", 6),
}
CLEAN_FILES = {"clean_prepared.php", "clean_sanitized.php", "clean_crypto.php", "clean_config.php",}

# These files contain code, that should be flagged, however the scanner in its current form
# does not find these
FALSE_NEGATIVE_FILES = {
    "FN_interprocedural.php",
    "FN_object_property.php",
    "FN_db_save.php",
    "FN_cross_file_input.php",
    "FN_cross_file_query.php",
    "FN_dynamic_hash.php",
    "FN_encoded_secret.php",
    "FN_dynamic_misconfig.php",
}



def test_scan_matches_expected_findings() -> None:
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR)
    found = {(f.file, f.rule_id, f.line) for f in result.findings}
    assert found == EXPECTED_FINDINGS


def test_clean_fixtures_stay_clean() -> None:
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR)
    assert not [finding for finding in result.findings if finding.file in CLEAN_FILES]


def test_findings_have_remediation_and_trace() -> None:
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR)
    for finding in result.findings:
        assert finding.remediation.strip()
        assert finding.snippet.strip()
        if finding.module_id == "a05_injection":  # taint-based findings carry a trace
            assert finding.taint_trace, f"{finding.rule_id} should carry a taint trace"


def test_module_filter_limits_scan() -> None:
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR, only_modules={"module_does_not_exist"})
    assert result.modules == []
    assert result.findings == []


def test_cli_exit_codes(tmp_path: Path, capsys) -> None:
    assert main(["scan", str(FIXTURES)]) == EXIT_FINDINGS

    clean_dir = tmp_path / "clean"
    clean_dir.mkdir()
    (clean_dir / "ok.php").write_text("<?php echo 'static';\n")
    assert main(["scan", str(clean_dir)]) == EXIT_CLEAN
    capsys.readouterr()


def test_modules_list_shows_all_modules(capsys) -> None:
    assert main(["modules", "list"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "a05_injection" in out
    assert "taint-based" in out
    assert "A05-SQLI-001" in out
    assert "a04_crypto_failures" in out
    assert "pattern-based" in out
    assert "A04-HASH-001" in out
    assert "a02_misconfiguration" in out
    assert "A02-TLS-001" in out


def test_module_filter_selects_single_module() -> None:
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR, only_modules={"a04_crypto_failures"})
    assert {f.module_id for f in result.findings} == {"a04_crypto_failures"}

def test_cli_modules_publish(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(REPO_ROOT)
    config_dir = tmp_path / "config"
    publish_a05_cmd = ["modules", "publish", "a05_injection", "--config-dir", str(config_dir)]

    assert main(publish_a05_cmd) == EXIT_CLEAN
    published = config_dir / "a05_injection.yaml"
    shipped = (MODULES_DIR / "a05_injection" / "config.yaml").read_text()
    assert published.read_text() == shipped

    # does not overwrite existing
    published.write_text("edited: true\n")
    assert main(publish_a05_cmd) == EXIT_ERROR
    assert published.read_text() == "edited: true\n"

    assert main(publish_a05_cmd + ["--force"]) == EXIT_CLEAN
    assert published.read_text() == shipped
    capsys.readouterr()

def test_cli_modules_publish_not_existing(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(REPO_ROOT)
    assert main(["modules", "publish", "not-existing", "--config-dir", str(tmp_path)]) == EXIT_ERROR
    assert "unknown module" in capsys.readouterr().err

def test_published_config_edit_changes_scan(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(REPO_ROOT)
    config_dir = tmp_path / "config"
    assert main(["modules", "publish", "a05_injection", "--config-dir", str(config_dir)]) == EXIT_CLEAN
    capsys.readouterr()

    published = config_dir / "a05_injection.yaml"
    config = yaml.safe_load(published.read_text())
    del config["taint_model"]["sinks"]["xss"] # remove css for the test
    published.write_text(yaml.safe_dump(config))

    result = run_scan(FIXTURES, config_dir=config_dir, modules_dir=MODULES_DIR,
                      only_modules={"a05_injection"})
    rule_ids = {f.rule_id for f in result.findings}

    assert "A05-XSS-001" not in rule_ids  # no xss found
    assert "A05-SQLI-001" in rule_ids  # everything else works

def test_known_false_negatives_stay_undetected() -> None:
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR)
    flagged = {finding.file for finding in result.findings} & FALSE_NEGATIVE_FILES
    assert flagged == set(), (
        f"somehow found a finding in {flagged}, that should have not been found"
    )


def test_php_ini_is_not_scanned() -> None:
    assert (FIXTURES / "php.ini").is_file()
    result = run_scan(FIXTURES, modules_dir=MODULES_DIR)
    assert "php.ini" not in {p.name for p in result.files}
    assert "php.ini" not in {f.file for f in result.findings}

def test_zipped_real_module_matches_folder_results(tmp_path: Path) -> None:
    import zipfile

    zip_modules_dir = tmp_path / "modules"
    zip_modules_dir.mkdir()
    source = MODULES_DIR / "a05_injection"
    with zipfile.ZipFile(zip_modules_dir / "a05_injection.zip", "w") as archive:
        for file in source.iterdir():
            archive.write(file, file.name)

    result = run_scan(FIXTURES, modules_dir=zip_modules_dir)
    found = {(f.file, f.rule_id, f.line) for f in result.findings}
    expected_a05 = {e for e in EXPECTED_FINDINGS if e[1].startswith("A05-")}
    assert found == expected_a05