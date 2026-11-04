from __future__ import annotations

import traceback
from importlib.metadata import entry_points
from pathlib import Path

from filewhy.plugin import Check, FileReport, Finding

ENTRY_POINT_GROUP = "filewhy.checks"


def discover_checks() -> dict[str, type[Check]]:
    found: dict[str, type[Check]] = {}
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        found[ep.name] = ep.load()
    return found


def analyze_file(
    path: Path, *, only: set[str] | None = None, skip: set[str] | None = None
) -> FileReport:
    checks = discover_checks()
    names = set(checks) if only is None else (set(checks) & only)
    if skip:
        names -= skip

    findings: list[Finding] = []
    for name in sorted(names):
        try:
            findings.extend(checks[name]().run(path))
        except Exception as exc:  # noqa: BLE001 -- aislar un check roto del resto del escaneo
            findings.append(
                Finding(
                    severity="medium", title=f"Check '{name}' falló: {exc}",
                    detail=traceback.format_exc(), check_error=True,
                )
            )
    return FileReport(path=str(path), findings=findings)


def analyze_path(
    root: Path, *, only: set[str] | None = None, skip: set[str] | None = None
) -> list[FileReport]:
    if root.is_file():
        files = [root]
    else:
        files = sorted(p for p in root.rglob("*") if p.is_file())

    return [analyze_file(f, only=only, skip=skip) for f in files]
