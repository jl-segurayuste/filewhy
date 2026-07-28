from __future__ import annotations

from pathlib import Path

from filewhy.plugin import Finding

# (nombre, firma de bytes, offset) -- de más específica a más genérica.
_SIGNATURES: list[tuple[str, bytes, int]] = [
    ("PDF", b"%PDF-", 0),
    ("ZIP", b"PK\x03\x04", 0),
    ("ZIP (vacío)", b"PK\x05\x06", 0),
    ("PE/EXE (Windows)", b"MZ", 0),
    ("ELF (Linux)", b"\x7fELF", 0),
    ("PNG", b"\x89PNG\r\n\x1a\n", 0),
    ("JPEG", b"\xff\xd8\xff", 0),
    ("GIF", b"GIF87a", 0),
    ("GIF", b"GIF89a", 0),
    ("GZIP", b"\x1f\x8b", 0),
]

# Extensión -> nombres de firma que serían normales para ella.
_EXPECTED: dict[str, set[str]] = {
    ".pdf": {"PDF"},
    ".zip": {"ZIP", "ZIP (vacío)"},
    ".jar": {"ZIP", "ZIP (vacío)"},
    ".apk": {"ZIP", "ZIP (vacío)"},
    ".docx": {"ZIP", "ZIP (vacío)"},
    ".xlsx": {"ZIP", "ZIP (vacío)"},
    ".pptx": {"ZIP", "ZIP (vacío)"},
    ".exe": {"PE/EXE (Windows)"},
    ".dll": {"PE/EXE (Windows)"},
    ".png": {"PNG"},
    ".jpg": {"JPEG"},
    ".jpeg": {"JPEG"},
    ".gif": {"GIF"},
    ".gz": {"GZIP"},
    ".tgz": {"GZIP"},
}


def detect_real_type(path: Path) -> str | None:
    try:
        header = path.read_bytes()[:16]
    except OSError:
        return None
    for name, magic, offset in _SIGNATURES:
        if header[offset : offset + len(magic)] == magic:
            return name
    return None


class FileIdentityCheck:
    """Compara el tipo real del fichero (firma de bytes) contra lo que su extensión promete."""

    name = "file_identity"

    def run(self, path: Path) -> list[Finding]:
        ext = path.suffix.lower()
        expected = _EXPECTED.get(ext)
        if expected is None:
            return []  # extensión no vigilada -- no aplica

        real_type = detect_real_type(path)
        if real_type is None:
            return []  # no reconocido -- podría ser texto plano legítimo, no forzar

        if real_type in expected:
            return []

        return [
            Finding(
                severity="high",
                title=f"Extensión '{ext}' pero el contenido real es {real_type}",
                detail="El fichero no es lo que su extensión afirma -- revisar antes de abrirlo o ejecutarlo.",
            )
        ]
