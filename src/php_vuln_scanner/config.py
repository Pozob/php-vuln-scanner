from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import yaml

CORE_CONFIG_FILE = "core.yaml"

DEFAULT_PHP_EXTENSIONS = [".php", ".php3", ".php4", ".php5", ".phtml", ".inc",]
DEFAULT_EXCLUDE_DIRS = [
    "vendor", # composer
    "node_modules", # npm, Bun, pnpm, etc.
    ".git", # git
]


@dataclass
class CoreConfig:
    """Loads and holds the default config, if no other is provided"""
    php_extensions: list[str] = field(default_factory=lambda: list(DEFAULT_PHP_EXTENSIONS))
    exclude_dirs: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_DIRS))


def load_core_config(config_dir: Path) -> CoreConfig:
    """Load the default config and merges it with a `core.yaml` if provided.

    Unsupported keys in the users config are rejected with a ValueError so that
    typos dont cause the config to fallback to default values without any warning"""
    config = CoreConfig()
    override_path = config_dir / CORE_CONFIG_FILE

    # Return early if no custom config is present
    if not override_path.is_file():
        return config

    custom_config = yaml.safe_load(override_path.read_text(encoding="utf-8"))
    if custom_config is None:
        return config
    if not isinstance(custom_config, dict):
        raise ValueError(f"{override_path}: expected a YAML, got {type(custom_config).__name__}")

    known_fields = set(CoreConfig.__dataclass_fields__)
    unknown_fields = set(custom_config) - known_fields
    if unknown_fields:
        raise ValueError(f"{override_path} contains unknown config: {', '.join(sorted(unknown_fields))}")

    for key, value in custom_config.items():
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError(f"{override_path}: '{key}' must be a list of strings")
        setattr(config, key, value)
    return config
