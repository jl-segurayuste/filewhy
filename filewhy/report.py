from __future__ import annotations

import json

from filewhy.plugin import SEVERITIES, FileReport

_SEVERITY_ORDER = {sev: idx for idx, sev in enumerate(SEVERITIES)}


def worst_severity(reports: list[FileReport]) -> str | None:
    sevs = [f.severity for r in reports for f in r.findings]
    if not sevs:
        return None
    return max(sevs, key=lambda s: _SEVERITY_ORDER[s])


def to_console(reports: list[FileReport]) -> str:
    with_findings = [r for r in reports if r.findings]
    if not with_findings:
        return f"{len(reports)} fichero(s) analizados, 0 hallazgo(s)."

    lines = []
    for r in with_findings:
        lines.append(f"── {r.path} " + "─" * max(0, 50 - len(r.path)))
        for f in r.findings:
            label = f"[{f.severity.upper():<6}]"
            lines.append(f"  {label} {f.title}")
            if f.detail:
                lines.append(f"           {f.detail}")
        lines.append("")

    total = sum(len(r.findings) for r in reports)
    lines.append(f"Total: {total} hallazgo(s) en {len(with_findings)} de {len(reports)} fichero(s).")
    return "\n".join(lines)


def to_json(reports: list[FileReport]) -> str:
    return json.dumps([r.model_dump() for r in reports], ensure_ascii=False, indent=2)
