from __future__ import annotations

import re
import zipfile
from pathlib import Path

from filewhy.plugin import Finding

_EXECUTABLE_SUFFIXES = {".exe", ".dll", ".so", ".sh", ".bat", ".cmd", ".ps1"}
_BOMB_RATIO_THRESHOLD = 100  # tamaño descomprimido / comprimido

# Unidad de Windows tipo "C:\..." o "C:/..." -- absoluto aunque no empiece
# por "/". El propio ZIP no obliga a usar "/" como separador: herramientas
# que crean el archivo en Windows (o construido a mano, como haría un
# atacante) pueden usar "\" -- Path(...).parts en Linux NO lo trata como
# separador, así que ".." solo se detectaría con "/". Por eso el traversal
# se busca sobre el nombre normalizado a "/" en vez de fiarse solo de
# Path(name).parts.
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


class ArchiveRiskCheck:
    """Riesgos estructurales en ZIP/JAR/APK/DOCX/XLSX (todos son contenedores ZIP):
    path traversal ("zip-slip"), miembros ejecutables, ratio de compresión sospechoso
    (posible zip bomb). Nunca extrae nada a disco -- solo lee los metadatos del índice.
    """

    name = "archive_risk"

    def run(self, path: Path) -> list[Finding]:
        try:
            if not zipfile.is_zipfile(path):
                return []
        except OSError:
            return []

        findings: list[Finding] = []
        try:
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    findings.extend(self._check_member(info))
        except (zipfile.BadZipFile, OSError, EOFError):
            return []

        return findings

    def _check_member(self, info: zipfile.ZipInfo) -> list[Finding]:
        findings: list[Finding] = []
        name = info.filename

        normalized = name.replace("\\", "/")
        if name.startswith("/") or _WINDOWS_DRIVE.match(name) or ".." in Path(normalized).parts:
            findings.append(
                Finding(
                    severity="high",
                    title=f"Path traversal en miembro del archivo: {name}",
                    detail="Extraer este ZIP tal cual podría escribir fuera del directorio destino ('zip-slip').",
                )
            )

        suffix = Path(name).suffix.lower()
        if suffix in _EXECUTABLE_SUFFIXES:
            findings.append(
                Finding(
                    severity="medium",
                    title=f"Miembro ejecutable dentro del archivo: {name}",
                    detail="Puede ser legítimo (p.ej. un APK real trae .so) -- revisar si es lo esperado.",
                )
            )

        if info.compress_size > 0:
            ratio = info.file_size / info.compress_size
            if ratio > _BOMB_RATIO_THRESHOLD and info.file_size > 10 * 1024 * 1024:
                findings.append(
                    Finding(
                        severity="high",
                        title=f"Ratio de compresión sospechoso en {name} ({ratio:.0f}x)",
                        detail="Posible zip bomb -- extraerlo podría agotar disco/memoria.",
                    )
                )

        return findings
