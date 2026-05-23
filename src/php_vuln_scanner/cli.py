from __future__ import annotations

import sys
import argparse
import logging
from pathlib import Path

from php_vuln_scanner.config import load_core_config
from php_vuln_scanner.file_finder import find_php_files
from php_vuln_scanner.file_parser import ParsingService

EXIT_CLEAN = 0
EXIT_ERROR = 1

def config_arguemnt_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phpscan",
        description="SAST Scanner for PHP Applications written for Bachelor Thesis",
    )

    parser.add_argument(
        "--version", action="version", version=f"%(prog)s 0.1"
    )

    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="Scan a PHP project")
    scan.add_argument("target", type=Path, help="Path to the project")
    scan.add_argument(
        "--modules",
        help="Comma separatet list of module ids to run (default: all discovered modules)",
    )
    scan.add_argument(
        "--format",
        choices=["json", "html", "term"],
        default="term",
        help="Output format (default: term for terminal. JSON is always written)",
    )
    scan.add_argument("--output", type=Path, help="Path for the report file")
    scan.add_argument(
        "--config-dir",
        type=Path,
        default=Path("config"),
        help="Directory with config overrides (default: ./config).",
    )
    scan.add_argument(
        "--verbose", action="store_true", help="Enable verbose output"
    )

    modules = subparsers.add_parser("modules", help="Manage scanner modules")
    modules_sub = modules.add_subparsers(dest="modules_command")
    modules_sub.add_parser("list", help="Show discovered modules and information about them")

    return parser

def cmd_scan(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    if not args.target.exists():
        print(f"error: target does not exist: {args.target}", file=sys.stderr)
        return EXIT_ERROR

    try:
        config = load_core_config(args.config_dir)
    except ValueError as exc:
        print(f"error: invalid config: {exc}", file=sys.stderr)
        return EXIT_ERROR

    scan_root = args.target if args.target.is_dir() else args.target.parent
    files = find_php_files(args.target, config)
    parsed = ParsingService().parse_files(files, scan_root)
    with_errors = [parsed_file for parsed_file in parsed if parsed_file.has_parse_errors]

    print(f"scanned '{args.target}'")
    print(f"PHP files found:  {len(files)}")
    print(f"parsed:           {len(parsed)}"
          + (f" ({len(with_errors)} with syntax errors)" if with_errors else ""))
    if args.verbose:
        for parsed_file in parsed:
            marker = " [syntax errors]" if parsed_file.has_parse_errors else ""
            print(f"{parsed_file.rel_path}{marker}")
    return EXIT_CLEAN


def cmd_list_modules() -> int:
    print("No modules discovered")
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    parser = config_arguemnt_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "modules":
        if args.modules_command == "list":
            return cmd_list_modules()
        parser.parse_args(["modules", "--help"])
        return EXIT_ERROR
    parser.print_help()
    return EXIT_CLEAN

if __name__ == "__main__":
    sys.exit(main())