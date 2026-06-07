from __future__ import annotations

from pathlib import Path
from php_vuln_scanner.module_loader import discover_modules

VALID_MANIFEST = """\
id: test
name: Test module
version: 0.0.1
owasp_category: "A00:2025"
description: A dummy module for loader tests.
entry_point: module.py
requires_taint_engine: false
"""

VALID_MODULE = """\
from php_vuln_scanner.findings import Finding, Rule, Severity
from php_vuln_scanner.module_api import ModuleContext, ScannerModule


class TestModule(ScannerModule):
    def rules(self):
        return [Rule("A00-TEST-001", None, Severity.LOW,
                     "Test issue.", "Test remediation.")]

    def analyze(self, parsed_files, context):
        return []
"""


def write_module(
    modules_dir: Path,
    name: str = "test",
    manifest: str = VALID_MANIFEST,
    module_py: str = VALID_MODULE,
    config_yaml: str = "setting: 1\n",
) -> Path:
    module_dir = modules_dir / name
    module_dir.mkdir(parents=True)
    (module_dir / "module.yaml").write_text(manifest)
    (module_dir / "module.py").write_text(module_py)
    (module_dir / "config.yaml").write_text(config_yaml)
    return module_dir


def test_valid_folder_module_loads(tmp_path: Path) -> None:
    write_module(tmp_path / "modules")
    (module,) = discover_modules(tmp_path / "modules", tmp_path / "config")
    assert module.manifest.id == "test"
    assert module.config == {"setting": 1}
    assert [r.rule_id for r in module.instance.rules()] == ["A00-TEST-001"]

def test_config_override_wins_over_shipped_defaults(tmp_path: Path) -> None:
    write_module(tmp_path / "modules")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "test.yaml").write_text("setting: 2\n")
    (module,) = discover_modules(tmp_path / "modules", config_dir)
    assert module.config == {"setting": 2}


def test_missing_manifest_key_skips_module(tmp_path: Path, caplog) -> None:
    broken = VALID_MANIFEST.replace("entry_point: module.py\n", "")
    write_module(tmp_path / "modules", manifest=broken)
    assert discover_modules(tmp_path / "modules", tmp_path / "config") == []
    assert "skipping module 'test'" in caplog.text
    assert "entry_point" in caplog.text


def test_rule_without_remediation_skips_module(tmp_path: Path, caplog) -> None:
    bad = VALID_MODULE.replace('"Test remediation."', '""')
    write_module(tmp_path / "modules", module_py=bad)
    assert discover_modules(tmp_path / "modules", tmp_path / "config") == []
    assert "remediation" in caplog.text


def test_crashing_entry_point_skips_module_but_others_load(tmp_path: Path, caplog) -> None:
    modules_dir = tmp_path / "modules"
    write_module(modules_dir, name="broken", module_py="raise RuntimeError('Test Exception')")
    write_module(modules_dir, name="test")
    (module,) = discover_modules(modules_dir, tmp_path / "config")
    assert module.manifest.id == "test"
    assert "skipping module 'broken'" in caplog.text


def test_non_module_folders_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "modules" / "not_a_module").mkdir(parents=True)
    assert discover_modules(tmp_path / "modules", tmp_path / "config") == []

def test_missing_config_yaml_skips_module(tmp_path: Path, caplog) -> None:
    module_dir = write_module(tmp_path / "modules")
    (module_dir / "config.yaml").unlink()
    assert discover_modules(tmp_path / "modules", tmp_path / "config") == []
    assert "no config found" in caplog.text
