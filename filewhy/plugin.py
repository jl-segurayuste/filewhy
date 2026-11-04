from __future__ import annotations

from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field

Severity = str
SEVERITIES: tuple[Severity, ...] = ("info", "low", "medium", "high")


class Finding(BaseModel):
    severity: Severity
    title: str
    detail: str = ""
    check_error: bool = False  # el check reventó: el fichero no se ha revisado del todo

    def model_post_init(self, context: object, /) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity {self.severity!r} no es una de {SEVERITIES}")


class FileReport(BaseModel):
    path: str
    findings: list[Finding] = Field(default_factory=list)


class Check(Protocol):
    name: str

    def run(self, path: Path) -> list[Finding]: ...
