from __future__ import annotations

import pytest
from pathlib import Path
from php_vuln_scanner.config import CoreConfig, load_core_config


def test_missing_config_dir_yields_defaults(tmp_path: Path) -> None:
    config = load_core_config(tmp_path / "nope")
    assert config == CoreConfig()
    assert ".php" in config.php_extensions
    assert "vendor" in config.exclude_dirs


def test_override_replaces_defaults(tmp_path: Path) -> None:
    (tmp_path / "core.yaml").write_text("php_extensions:\n  - .php\n")
    config = load_core_config(tmp_path)
    assert config.php_extensions == [".php"]
    assert config.exclude_dirs == CoreConfig().exclude_dirs  # untouched


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "core.yaml").write_text("unknown_key:\n  - .php\n")
    with pytest.raises(ValueError, match="contains unknown config: unknown_key"):
        load_core_config(tmp_path)


def test_wrong_value_type_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "core.yaml").write_text("php_extensions: .php\n")
    with pytest.raises(ValueError, match="must be a list of strings"):
        load_core_config(tmp_path)


def test_empty_file_yields_defaults(tmp_path: Path) -> None:
    (tmp_path / "core.yaml").write_text("")
    assert load_core_config(tmp_path) == CoreConfig()
