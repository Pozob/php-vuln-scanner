from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from php_vuln_scanner.module_loader import discover_modules
from php_vuln_scanner.reporting import build_report, render_html, render_terminal, write_json_report
from php_vuln_scanner.scanner import default_modules_dir, run_scan

EXIT_CLEAN = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2

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
        "-f",
        choices=["json", "html", "term"],
        action="append",
        help="Output format (default: term for terminal)",
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

    publish = modules_sub.add_parser(
        "publish",
        help="Copy a modules default config into the config dir for editing",
    )
    publish.add_argument("module_id", help="Id of the module whose config to publish.")
    publish.add_argument(
        "--config-dir",
        type=Path,
        default=Path("config"),
        help="Config dir to copy to (default: ./config).",
    )
    publish.add_argument(
        "--force",
        action="store_true",
        help="Force the write of the config file",
    )

    return parser

def cmd_scan(args: argparse.Namespace) -> int:
    """Run a full scan"""
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    if not args.target.exists():
        print(f"error: target path does not exist: {args.target}", file=sys.stderr)
        return EXIT_ERROR

    only = {module.strip() for module in args.modules.split(",") if module.strip()} if args.modules else None
    try:
        result = run_scan(args.target, config_dir=args.config_dir, only_modules=only)
    except ValueError as exc:
        print(f"error: invalid config: {exc}", file=sys.stderr)
        return EXIT_ERROR

    report = build_report(result)
    target_name = args.target.name or "scan"

    format = args.format or ["term"]

    try:
        if "json" in format:
            json_path = args.output if args.output else Path(f"{target_name}.phpscan.json")
            write_json_report(report, json_path)
            print(f"JSON report written to {json_path}")
        if "term" in format:
            print(render_terminal(result, verbose=args.verbose))
        if "html" in format:
            html_path = args.output or Path(f"{target_name}.phpscan.html")
            html_path.write_text(render_html(report), encoding="utf-8")
            print(f"HTML report written to {html_path}")
    except OSError as exc:
        print(f"cannot write report: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return EXIT_FINDINGS if result.findings else EXIT_CLEAN

def cmd_list_modules() -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    modules = discover_modules(default_modules_dir(), Path("config"))
    if not modules:
        print("No modules discovered.")
        return EXIT_CLEAN
    for module in modules:
        manifest = module.manifest
        type = "taint-based" if manifest.requires_taint_engine else "pattern-based"
        print(f"{manifest.id}  v{manifest.version}  {manifest.owasp_category}  {type}")
        print(f"{manifest.name} - {manifest.description}")
        print(f"rules: {', '.join(rule.rule_id for rule in module.instance.rules())}")
    return EXIT_CLEAN

def cmd_modules_publish(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    modules = discover_modules(default_modules_dir(), args.config_dir)
    module = next((mod for mod in modules if mod.manifest.id == args.module_id), None)

    if module is None:
        known = ", ".join(mod.manifest.id for mod in modules) or "none"
        print(f"error: unknown module '{args.module_id}' (available are: {known})", file=sys.stderr)
        return EXIT_ERROR

    destination = args.config_dir / f"{module.manifest.id}.yaml"
    if destination.exists() and not args.force:
        print(
            f"error: {destination} already exists. Edit it or pass --force to overwrite",
            file=sys.stderr,
        )
        return EXIT_ERROR

    args.config_dir.mkdir(parents=True, exist_ok=True)
    destination.write_text(module.config_defaults_text, encoding="utf-8")

    print(f"published config of '{module.manifest.id}' to {destination}")
    print("Edit this file to customize the module. It replaces the default config")

    return EXIT_CLEAN

def main(argv: list[str] | None = None) -> int:
    parser = config_arguemnt_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "modules":
        if args.modules_command == "list":
            return cmd_list_modules()
        if args.modules_command == "publish":
            return cmd_modules_publish(args)
        parser.parse_args(["modules", "--help"])
        return EXIT_ERROR
    parser.print_help()
    return EXIT_CLEAN

if __name__ == "__main__":
    sys.exit(main())