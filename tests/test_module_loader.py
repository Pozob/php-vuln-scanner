from __future__ import annotations

import zipfile
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


def _write_module(
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

def _write_zip_module(
    modules_dir: Path,
    name: str = "test",
    wrap_folder: str = "",
    manifest: str = VALID_MANIFEST,
    extra_paths: str | None = None,
) -> Path:
    modules_dir.mkdir(parents=True, exist_ok=True)
    zip_path = modules_dir / f"{name}.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(f"{wrap_folder}module.yaml", manifest)
        archive.writestr(f"{wrap_folder}module.py", VALID_MODULE)
        archive.writestr(f"{wrap_folder}config.yaml", "setting: 1\n")
        if extra_paths is not None:
            archive.writestr(extra_paths, "x")

    return zip_path


def test_valid_folder_module_loads(tmp_path: Path) -> None:
    _write_module(tmp_path / "modules")
    (module,) = discover_modules(tmp_path / "modules", tmp_path / "config")
    assert module.manifest.id == "test"
    assert module.config == {"setting": 1}
    assert [r.rule_id for r in module.instance.rules()] == ["A00-TEST-001"]

def test_config_override_wins_over_shipped_defaults(tmp_path: Path) -> None:
    _write_module(tmp_path / "modules")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "test.yaml").write_text("setting: 2\n")
    (module,) = discover_modules(tmp_path / "modules", config_dir)
    assert module.config == {"setting": 2}


def test_missing_manifest_key_skips_module(tmp_path: Path, caplog) -> None:
    broken = VALID_MANIFEST.replace("entry_point: module.py\n", "")
    _write_module(tmp_path / "modules", manifest=broken)
    assert discover_modules(tmp_path / "modules", tmp_path / "config") == []
    assert "skipping module 'test'" in caplog.text
    assert "entry_point" in caplog.text


def test_rule_without_remediation_skips_module(tmp_path: Path, caplog) -> None:
    bad = VALID_MODULE.replace('"Test remediation."', '""')
    _write_module(tmp_path / "modules", module_py=bad)
    assert discover_modules(tmp_path / "modules", tmp_path / "config") == []
    assert "remediation" in caplog.text


def test_crashing_entry_point_skips_module_but_others_load(tmp_path: Path, caplog) -> None:
    modules_dir = tmp_path / "modules"
    _write_module(modules_dir, name="broken", module_py="raise RuntimeError('Test Exception')")
    _write_module(modules_dir, name="test")
    (module,) = discover_modules(modules_dir, tmp_path / "config")
    assert module.manifest.id == "test"
    assert "skipping module 'broken'" in caplog.text


def test_non_module_folders_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "modules" / "not_a_module").mkdir(parents=True)
    assert discover_modules(tmp_path / "modules", tmp_path / "config") == []

def test_missing_config_yaml_skips_module(tmp_path: Path, caplog) -> None:
    module_dir = _write_module(tmp_path / "modules")
    (module_dir / "config.yaml").unlink()
    assert discover_modules(tmp_path / "modules", tmp_path / "config") == []
    assert "no config found" in caplog.text


def test_zip_module_loads_like_folder(tmp_path: Path) -> None:
    _write_zip_module(tmp_path / "modules")
    (module,) = discover_modules(tmp_path / "modules", tmp_path / "config")
    assert module.manifest.id == "test"
    assert module.config == {"setting": 1}
    assert "setting: 1" in module.config_defaults_text  # publish works for ZIPs
    assert [rules.rule_id for rules in module.instance.rules()] == ["A00-TEST-001"]


def test_zip_with_wrapping_folder_loads(tmp_path: Path) -> None:
    _write_zip_module(tmp_path / "modules", wrap_folder="test/")
    (module,) = discover_modules(tmp_path / "modules", tmp_path / "config")
    assert module.manifest.id == "test"


def test_zip_respects_custom_config(tmp_path: Path) -> None:
    _write_zip_module(tmp_path / "modules")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "test.yaml").write_text("setting: 2\n")
    (module,) = discover_modules(tmp_path / "modules", config_dir)
    assert module.config == {"setting": 2}


def test_corrupt_zip_is_skipped(tmp_path: Path, caplog) -> None:
    modules_dir = tmp_path / "modules"
    _write_module(modules_dir)
    (modules_dir / "broken.zip").write_bytes(b"my very broken zip file")
    (module,) = discover_modules(modules_dir, tmp_path / "config")
    assert module.manifest.id == "test"
    assert "skipping module 'broken.zip'" in caplog.text


def test_zip_without_manifest_is_skipped(tmp_path: Path, caplog) -> None:
    modules_dir = tmp_path / "modules"
    modules_dir.mkdir()
    with zipfile.ZipFile(modules_dir / "empty.zip", "w") as archive:
        archive.writestr("readme.txt", "nothing here")
    assert discover_modules(modules_dir, tmp_path / "config") == []
    assert "does not contain module.yaml" in caplog.text


def test_zip_with_path_traversal_is_rejected(tmp_path: Path, caplog) -> None:
    _write_zip_module(tmp_path / "modules", extra_paths="../very_evil.txt")
    assert discover_modules(tmp_path / "modules", tmp_path / "config") == []
    assert "unsafe path" in caplog.text
    assert not (tmp_path / "very_evil.txt").exists()


def test_folder_wins_over_zip_with_same_id(tmp_path: Path, caplog) -> None:
    modules_dir = tmp_path / "modules"
    _write_module(modules_dir, config_yaml="setting: from_folder\n")
    _write_zip_module(modules_dir)
    (module,) = discover_modules(modules_dir, tmp_path / "config")
    assert module.config == {"setting": "from_folder"}
    assert "duplicate module id 'test'" in caplog.text
