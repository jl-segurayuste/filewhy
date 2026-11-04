from __future__ import annotations

import re
import stat
import zipfile
from pathlib import Path

from filewhy.plugin import Finding

_EXECUTABLE_SUFFIXES = {
    ".exe", ".dll", ".so", ".sh", ".bat", ".cmd", ".ps1",
    # Los de las campañas de malware por correo: accesos directos, salvapantallas, instaladores…
    ".lnk", ".scr", ".pif", ".cpl", ".msi", ".com", ".reg",
}
# Scripts que Windows ejecuta con doble clic. Solo cuentan en la raíz del archivo: dentro de
# carpetas (una web, un proyecto) un .js es lo normal.
_ROOT_SCRIPT_SUFFIXES = {".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta"}
_BOMB_RATIO_THRESHOLD = 100  # tamaño descomprimido / comprimido
_BOMB_TOTAL_BYTES = 1024 ** 3

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
                infos = zf.infolist()
                for info in infos:
                    findings.extend(self._check_member(info))
        except (zipfile.BadZipFile, OSError, EOFError):
            return []

        # Bomba repartida en muchos miembros (cada uno por debajo del umbral individual)
        total = sum(i.file_size for i in infos)
        packed = sum(i.compress_size for i in infos)
        if total > _BOMB_TOTAL_BYTES and packed and total / packed > _BOMB_RATIO_THRESHOLD and not any(
            f.title.startswith("Ratio de compresión") for f in findings
        ):
            findings.append(
                Finding(
                    severity="high",
                    title=f"El archivo se expande a {total // 1024 ** 2} MB ({total / packed:.0f}x)",
                    detail="Posible zip bomb repartida en varios miembros.",
                )
            )

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

        if stat.S_ISLNK(info.external_attr >> 16):
            findings.append(
                Finding(
                    severity="high",
                    title=f"Enlace simbólico dentro del archivo: {name}",
                    detail="Al extraerlo puede apuntar fuera del destino y hacer que otro miembro escriba allí.",
                )
            )

        if info.flag_bits & 0x1:
            findings.append(
                Finding(
                    severity="medium",
                    title=f"Miembro cifrado: {name}",
                    detail="Su contenido no se puede revisar sin la contraseña (táctica habitual para esquivar antivirus).",
                )
            )

        lower = normalized.lower()
        if lower.endswith("vbaproject.bin"):
            findings.append(
                Finding(
                    severity="high",
                    title="El documento contiene macros VBA",
                    detail="Se ejecutan al habilitar el contenido -- no habilitarlas sin revisar.",
                )
            )
        elif "/embeddings/" in lower and lower.endswith(".bin"):
            findings.append(
                Finding(
                    severity="medium",
                    title=f"Objeto OLE incrustado: {name}",
                    detail="Puede contener un ejecutable o un documento con macros.",
                )
            )

        suffix = Path(normalized).suffix.lower()
        if suffix in _ROOT_SCRIPT_SUFFIXES and "/" not in normalized.strip("/"):
            findings.append(
                Finding(
                    severity="high",
                    title=f"Script ejecutable en la raíz del archivo: {name}",
                    detail="Windows lo ejecuta con un doble clic -- típico de adjuntos maliciosos.",
                )
            )
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
