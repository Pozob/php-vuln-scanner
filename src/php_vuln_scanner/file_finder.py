from __future__ import annotations

from pathlib import Path
from php_vuln_scanner.config import CoreConfig


def find_php_files(target: Path, config: CoreConfig) -> list[Path]:
    """Returns all PHP files in target path.
    target can be a directory or a file. if target is a directory, all PHP files in that directory are considered.
    If target is a file, it will be returned without checking the extension
    """
    if target.is_file():
        return [target]

    dirs_to_exclude = set(config.exclude_dirs)
    extensions = {ext.lower() for ext in config.php_extensions}
    files: list[Path] = []
    for path in target.rglob("*"):
        if any(part in dirs_to_exclude for part in path.relative_to(target).parts[:-1]):
            continue
        if path.is_file() and path.suffix.lower() in extensions:
            files.append(path)
    return sorted(files)
