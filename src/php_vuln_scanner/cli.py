from __future__ import annotations

import sys
import argparse
from pathlib import Path

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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = config_arguemnt_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        pass
    parser.print_help()
    return EXIT_CLEAN

if __name__ == "__main__":
    sys.exit(main())