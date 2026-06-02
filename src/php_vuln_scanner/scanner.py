from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from php_vuln_scanner.file_parser import ParsedFile, ParsingService
from php_vuln_scanner.config import CoreConfig, load_core_config
from php_vuln_scanner.file_finder import find_php_files
from php_vuln_scanner.findings import Finding
from php_vuln_scanner.module_api import ModuleContext
from php_vuln_scanner.module_loader import LoadedModule, discover_modules

logger = logging.getLogger(__name__)


def default_modules_dir() -> Path:
    cwd_modules = Path("modules")
    if cwd_modules.is_dir():
        return cwd_modules
    return Path(__file__).resolve().parents[2] / "modules"


@dataclass(frozen=True)
class ScanResult:
    """Collection of everything a scan produced, so it can be
    used in a report"""

    target: Path
    files: list[Path]
    parsed_files: list[ParsedFile]
    modules: list[LoadedModule]
    findings: list[Finding]
    core_config: CoreConfig


def run_scan(
    target: Path,
    config_dir: Path = Path("config"),
    modules_dir: Path | None = None,
    only_modules: set[str] | None = None,
) -> ScanResult:
    """Run the actual scan"""
    core_config = load_core_config(config_dir)
    scan_root = target if target.is_dir() else target.parent
    files = find_php_files(target, core_config)

    parsing = ParsingService()
    parsed_files = parsing.parse_files(files, scan_root)

    modules = discover_modules(modules_dir or default_modules_dir(), config_dir)
    # respect the user decision if only specific modules should run
    if only_modules is not None:
        unknown = only_modules - {m.manifest.id for m in modules}
        for module_id in sorted(unknown):
            logger.warning("requested module not found: %s", module_id)
        modules = [module for module in modules if module.manifest.id in only_modules]

    findings: list[Finding] = []
    for module in modules:
        context = ModuleContext(
            module_id=module.manifest.id,
            owasp_category=module.manifest.owasp_category,
            config=module.config,
            parsing=parsing,
        )
        try:
            findings.extend(module.instance.analyze(parsed_files, context))
        except Exception:
            logger.exception("module '%s' failed during analysis and its results are discarded", module.manifest.id)

    findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return ScanResult(
        target=target,
        files=files,
        parsed_files=parsed_files,
        modules=modules,
        findings=findings,
        core_config=core_config,
    )
