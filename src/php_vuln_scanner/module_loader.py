from __future__ import annotations

import importlib.util
import inspect
import logging
from dataclasses import dataclass
from pathlib import Path
import yaml

from php_vuln_scanner.findings import Rule
from php_vuln_scanner.module_api import ScannerModule

logger = logging.getLogger(__name__)

_REQUIRED_MANIFEST_KEYS = (
    "id",
    "name",
    "version",
    "owasp_category",
    "description",
    "entry_point",
    "config_file",
)

MANIFEST_FILENAME = "module.yaml"


@dataclass(frozen=True)
class ModuleManifest:
    """Validates the content of a module.yaml"""

    id: str
    name: str
    version: str
    owasp_category: str
    description: str
    entry_point: str
    config_file: str
    requires_taint_engine: bool = False

    @classmethod
    def from_file(cls, path: Path) -> ModuleManifest:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))

        if not isinstance(data, dict):
            raise ValueError(f"{path}: manifest must be a YAML mapping")

        missing = [key for key in _REQUIRED_MANIFEST_KEYS if not isinstance(data.get(key), str) or not data[key].strip()]
        if missing:
            raise ValueError(f"{path}: missing or invalid manifest keys: {', '.join(missing)}")

        requires = data.get("requires_taint_engine", False)
        if not isinstance(requires, bool):
            raise ValueError(f"{path}: requires_taint_engine must be a boolean")

        return cls(
            **{key: data[key].strip() for key in _REQUIRED_MANIFEST_KEYS},
            requires_taint_engine=requires,
        )


@dataclass(frozen=True)
class LoadedModule:
    manifest: ModuleManifest
    instance: ScannerModule
    config: dict
    path: Path


def discover_modules(modules_dir: Path, config_dir: Path) -> list[LoadedModule]:
    """Load all valid folder modules from `modules_dir` but skip broken ones"""
    if not modules_dir.is_dir():
        logger.warning("modules directory not found: %s", modules_dir)
        return []

    loaded = []
    for entry in sorted(modules_dir.iterdir()):
        if not entry.is_dir() or not (entry / MANIFEST_FILENAME).is_file():
            continue
        try:
            loaded.append(_load_module(entry, config_dir))
        except Exception as exc:
            logger.warning("skipping module '%s': %s", entry.name, exc)
    return loaded


def _load_module(module_dir: Path, config_dir: Path) -> LoadedModule:
    # Load the manifest and the instance of the module
    manifest = ModuleManifest.from_file(module_dir / MANIFEST_FILENAME)
    instance = _instantiate_entry_point(module_dir / manifest.entry_point, manifest.id)

    _validate_rules(instance, manifest.id)
    config = _load_module_config(module_dir, config_dir, manifest.config_file)

    return LoadedModule(manifest=manifest, instance=instance, config=config, path=module_dir)


def _instantiate_entry_point(entry_path: Path, module_id: str) -> ScannerModule:
    if not entry_path.is_file():
        raise ValueError(f"entry point does not exist: {entry_path.name}")

    spec = importlib.util.spec_from_file_location(f"php_vuln_scanner_module_{module_id}", entry_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import entry point {entry_path.name}")

    py_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(py_module)

    # Inheritance chacking
    classes = [
        obj
        for _, obj in inspect.getmembers(py_module, inspect.isclass)
        if issubclass(obj, ScannerModule) and obj is not ScannerModule
    ]
    if len(classes) != 1:
        raise ValueError(
            f"entry point must define exactly one ScannerModule subclass, found {len(classes)}"
        )

    return classes[0]()


def _validate_rules(instance: ScannerModule, module_id: str) -> None:
    """Validate rules for uniqueness and basic structure"""
    rules = instance.rules()
    if not rules or not all(isinstance(rule, Rule) for rule in rules):
        raise ValueError("rules() must return a non-empty list of Rule objects")

    rule_ids = [rule.rule_id for rule in rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError(f"duplicate rule_ids in module {module_id}")


def _load_module_config(module_dir: Path, config_dir: Path, config_file: str) -> dict:
    """Load the module config. It can be loaded from 2 places: in the module
    and in the config folder. If both are present, the config folder takes
    priority.
    """
    override = config_dir / config_file
    defaults = module_dir / config_file
    path = override if override.is_file() else defaults

    if not path.is_file():
        raise ValueError(f"config file {config_file} not found in module or config dir")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError(f"{path}: module config must be a YAML mapping")
    return data
