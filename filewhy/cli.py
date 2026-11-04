from __future__ import annotations

import argparse
import sys
from pathlib import Path

from filewhy.plugin import SEVERITIES
from filewhy.report import to_console, to_json, worst_severity
from filewhy.runner import analyze_path, discover_checks

_SEVERITY_ORDER = {sev: idx for idx, sev in enumerate(SEVERITIES)}


def _cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.path).resolve()
    only = set(args.only) if args.only else None
    skip = set(args.skip) if args.skip else None

    # Sin esto, una ruta mal escrita o un check con errata daban «0 hallazgos» y exit 0.
    if not path.exists():
        print(f"error: {path} no existe", file=sys.stderr)
        return 2
    unknown = ((only or set()) | (skip or set())) - set(discover_checks())
    if unknown:
        print(f"error: check(s) desconocido(s): {', '.join(sorted(unknown))} "
              "(ver `filewhy list-checks`)", file=sys.stderr)
        return 2

    reports = analyze_path(path, only=only, skip=skip)

    if args.json:
        print(to_json(reports))
    else:
        print(to_console(reports))

    if args.fail_on:
        worst = worst_severity(reports)
        if worst is not None and _SEVERITY_ORDER[worst] >= _SEVERITY_ORDER[args.fail_on]:
            return 1
    return 0


def _cmd_list_checks(args: argparse.Namespace) -> int:
    for name, cls in sorted(discover_checks().items()):
        doc = (cls.__doc__ or "").strip().splitlines()[0] if cls.__doc__ else ""
        print(f"{name}: {doc}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="filewhy")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Analiza un fichero o carpeta")
    p_scan.add_argument("path")
    p_scan.add_argument("--only", action="append", help="Ejecutar solo este check (repetible)")
    p_scan.add_argument("--skip", action="append", help="Saltar este check (repetible)")
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--fail-on", choices=SEVERITIES, default=None)
    p_scan.set_defaults(func=_cmd_scan)

    p_list = sub.add_parser("list-checks", help="Lista los checks instalados")
    p_list.set_defaults(func=_cmd_list_checks)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
