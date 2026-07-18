from __future__ import annotations

import importlib.util
import inspect
import logging
import zipfile
import tempfile
import yaml
from dataclasses import dataclass
from pathlib import Path

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
)

MODULE_MANIFEST_FILENAME = "module.yaml"
MODULE_CONFIG_FILENAME = "config.yaml"


@dataclass(frozen=True)
class ModuleManifest:
    """Represents a manifest file"""

    id: str
    name: str
    version: str
    owasp_category: str
    description: str
    entry_point: str
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
    config_defaults_text: str


def discover_modules(modules_dir: Path, config_dir: Path) -> list[LoadedModule]:
    """Load all valid folder and zip modules from `modules_dir` but skip broken ones

    On a duplicate module, the folder wins and will be used instead of the zip.
    Folders are used for development, while zip files contain a finished module
    """
    if not modules_dir.is_dir():
        logger.warning("modules directory not found: %s", modules_dir)
        return []

    loaded: list[LoadedModule] = []
    seen_ids: set[str] = set()

    for entry in sorted(modules_dir.iterdir()):
        try:
            # deveolpment module
            if entry.is_dir() and (entry / MODULE_MANIFEST_FILENAME).is_file():
                module = _load_module(entry, config_dir)
            # shipped modules
            elif entry.is_file() and entry.suffix.lower() == ".zip":
                module = _load_module(_extract_zip_module(entry), config_dir)
            else:
                continue

            if module.manifest.id in seen_ids:
                logger.warning(
                    "skipping module '%s': duplicate module id '%s'",
                    entry.name, module.manifest.id,
                )
                continue
            seen_ids.add(module.manifest.id)
            loaded.append(module)
        except Exception as exc:
            logger.warning("skipping module '%s': %s", entry.name, exc)
    return loaded


# The extracted zip files are deleted after the program exits
_extracted_zip_dirs: list[tempfile.TemporaryDirectory] = []

def _extract_zip_module(zip_path: Path) -> Path:
    """Extract a module ZIP to a temp dir and return the module root inside it."""
    with zipfile.ZipFile(zip_path) as archive:
        for name in archive.namelist():
            if Path(name).is_absolute() or ".." in Path(name).parts:
                raise ValueError(f"unsafe path in archive: {name!r}")

        tmp = tempfile.TemporaryDirectory(prefix=f"phpscan_{zip_path.stem}_")
        archive.extractall(tmp.name)
    # Keep the temp files for the process lifetime
    _extracted_zip_dirs.append(tmp)

    root = Path(tmp.name)
    if (root / MODULE_MANIFEST_FILENAME).is_file():
        return root

    # fallback for one wrapper folder
    entries = list(root.iterdir())
    if len(entries) == 1 and entries[0].is_dir() and (entries[0] / MODULE_MANIFEST_FILENAME).is_file():
        return entries[0]

    raise ValueError(f"archive does not contain {MODULE_MANIFEST_FILENAME} at its root")


def _load_module(module_dir: Path, config_dir: Path) -> LoadedModule:
    manifest = ModuleManifest.from_file(module_dir / MODULE_MANIFEST_FILENAME)
    instance = _instantiate_entry_point(module_dir / manifest.entry_point, manifest.id)
    _validate_rules(instance, manifest.id)
    config = _load_module_config(module_dir, config_dir, manifest.id)
    defaults_path = module_dir / MODULE_CONFIG_FILENAME
    defaults_text = defaults_path.read_text(encoding="utf-8") if defaults_path.is_file() else ""
    return LoadedModule(
        manifest=manifest,
        instance=instance,
        config=config,
        path=module_dir,
        config_defaults_text=defaults_text,
    )


def _instantiate_entry_point(entry_path: Path, module_id: str) -> ScannerModule:
    if not entry_path.is_file():
        raise ValueError(f"entry point does not exist: {entry_path.name}")

    spec = importlib.util.spec_from_file_location(f"php_vuln_scanner_module_{module_id}", entry_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import entry point {entry_path.name}")

    py_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(py_module)

    # Inheritance checking
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
    """Load-time rule validation: Rule construction itself enforces that a
    remediation exists; here we enforce the rule list is sane and unique."""
    rules = instance.rules()
    if not rules or not all(isinstance(rule, Rule) for rule in rules):
        raise ValueError("rules() must return a non-empty list of Rule objects")
    rule_ids = [rule.rule_id for rule in rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError(f"duplicate rule_ids in module {module_id}")


def _load_module_config(module_dir: Path, config_dir: Path, module_id: str) -> dict:
    """Load the module config. It can be loaded from 2 places: in the module
    and in the config folder. If both are present, the config folder takes
    priority.
    """
    override = config_dir / f"{module_id}.yaml"
    defaults = module_dir / MODULE_CONFIG_FILENAME
    path = override if override.is_file() else defaults

    if not path.is_file():
        raise ValueError(
            f"no config found: neither {defaults} nor override {override} exists"
        )

    data = yaml.safe_load(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError(f"{path}: module config must be a YAML mapping")
    return data
