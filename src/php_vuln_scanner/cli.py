from __future__ import annotations

import sys
import argparse
import logging
from pathlib import Path

from php_vuln_scanner.findings import Severity
from php_vuln_scanner.module_loader import discover_modules
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

    with_errors = [parsed_file for parsed_file in result.parsed_files if parsed_file.has_parse_errors]
    print(f"php vuln scanner - scanned '{args.target}'")
    print(f"PHP files found:  {len(result.files)}")
    print(f"parsed:           {len(result.parsed_files)}"
       + (f"({len(with_errors)} with syntax errors)" if with_errors else ""))
    print(f"modules run:      {', '.join(m.manifest.id for m in result.modules) or 'none'}")

    counts = {sev: sum(1 for f in result.findings if f.severity == sev) for sev in Severity}
    summary = ", ".join(f"{sev}: {n}" for sev, n in counts.items() if n)
    print(f"findings:         {len(result.findings)}" + (f" ({summary})" if summary else ""))

    for severity in Severity:
        group = [finding for finding in result.findings if finding.severity == severity]
        if not group:
            continue
        print(f"\n{severity} severity:")
        for finding in group:
            print(f"  {finding.file}:{finding.line}  {finding.rule_id}  {finding.message}")
            if args.verbose:
                print(f"snippet:     {finding.snippet}")
                print(f"remediation: {finding.remediation}")
                for step in finding.taint_trace or ():
                    print(f"trace: line {step.line}: {step.description}")

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