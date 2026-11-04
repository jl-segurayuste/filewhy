from __future__ import annotations

import logging
import re
from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from filewhy.plugin import Finding

# pypdf avisa por stderr de cada PDF malformado («invalid pdf header»…) y ensuciaba el informe.
logging.getLogger("pypdf").setLevel(logging.ERROR)

# Acciones que hacen algo más que navegar. Se buscan en la apertura (/OpenAction), en las acciones
# adicionales (/AA) del documento, de las páginas y de los campos de formulario, y en las
# anotaciones: antes solo se miraba el árbol /Names, y un /Launch en un enlace pasaba sin aviso.
_RISKY_ACTIONS = {
    "/JavaScript": ("high", "ejecuta JavaScript"),
    "/Launch": ("high", "abre un programa o fichero externo (/Launch)"),
    "/SubmitForm": ("medium", "envía los datos del formulario a un servidor (/SubmitForm)"),
    "/ImportData": ("medium", "importa datos de un fichero externo (/ImportData)"),
}


def _looks_like_pdf(path: Path) -> bool:
    """Por la firma: la cabecera %PDF- puede estar en los primeros 1024 bytes. Antes solo se miraba
    la extensión y un PDF sin ella (adjunto «factura») no se analizaba."""
    if path.suffix.lower() == ".pdf":
        return True
    try:
        with path.open("rb") as f:
            return b"%PDF-" in f.read(1024)
    except OSError:
        return False


_RAW_NAME_RE = re.compile(rb"/([A-Za-z0-9#]{2,40})")
_RAW_TOKENS = {
    "JavaScript": ("high", "El PDF contiene JavaScript"),
    "JS": ("high", "El PDF contiene JavaScript"),
    "Launch": ("high", "El PDF abre un programa o fichero externo (/Launch)"),
    "OpenAction": ("medium", "El PDF ejecuta una acción al abrirse (/OpenAction)"),
    "AA": ("medium", "El PDF tiene acciones automáticas (/AA)"),
    "EmbeddedFile": ("medium", "El PDF lleva ficheros embebidos (/EmbeddedFile)"),
    "SubmitForm": ("medium", "El PDF envía datos de formulario a un servidor (/SubmitForm)"),
    "ImportData": ("medium", "El PDF importa datos de un fichero externo (/ImportData)"),
}


def _raw_scan(path: Path) -> list[Finding]:
    """Revisión a nivel de bytes, para cuando pypdf no puede leer la estructura.

    Los PDF maliciosos suelen ir malformados a propósito (sin xref, offsets rotos): los lectores
    los reparan y los abren, pero pypdf fallaba y el fichero salía como limpio. Los nombres se
    normalizan (`/J#61vaScript` es `/JavaScript`), como hace pdfid."""
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if b"%PDF-" not in data[:1024]:
        return []  # no es un PDF (otro check se encarga de la extensión engañosa)
    names = {
        re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), m.group(1)).decode("latin-1")
        for m in _RAW_NAME_RE.finditer(data)
    }
    findings = [
        Finding(
            severity="medium",
            title="PDF malformado: no se pudo leer su estructura, revisado a nivel de bytes",
            detail="Los lectores suelen reparar estos PDF y abrirlos igual. Si el contenido va "
            "comprimido en flujos de objetos, esta revisión puede no verlo.",
        )
    ]
    seen: set[str] = set()
    for token, (severity, title) in _RAW_TOKENS.items():
        if token in names and title not in seen:
            seen.add(title)
            findings.append(Finding(severity=severity, title=title,
                                    detail="Detectado en los bytes del fichero, no en su estructura."))
    return findings


def _resolve(obj):
    return obj.get_object() if hasattr(obj, "get_object") else obj


def _iter_actions(obj, depth: int = 0):
    """La acción `obj` y las encadenadas con /Next."""
    obj = _resolve(obj)
    if depth > 20 or not hasattr(obj, "get") or "/S" not in obj:
        return
    yield obj
    nxt = _resolve(obj.get("/Next"))
    for item in (nxt if isinstance(nxt, list) else [nxt]) if nxt is not None else []:
        yield from _iter_actions(item, depth + 1)


def _additional_actions(obj):
    aa = _resolve(obj.get("/AA")) if hasattr(obj, "get") else None
    if hasattr(aa, "values"):
        for value in aa.values():
            yield from _iter_actions(value)


def _form_fields(fields, depth: int = 0):
    for ref in _resolve(fields) or []:
        field = _resolve(ref)
        if not hasattr(field, "get") or depth > 20:
            continue
        yield field
        if "/Kids" in field:
            yield from _form_fields(field["/Kids"], depth + 1)


class PdfRiskCheck:
    """Señales de riesgo en PDF: JavaScript embebido, acción de apertura automática,
    ficheros embebidos, y si está cifrado. Solo inspecciona la estructura de objetos
    del PDF -- nunca ejecuta ningún JavaScript ni abre ningún fichero embebido.
    """

    name = "pdf_risk"

    def run(self, path: Path) -> list[Finding]:
        if not _looks_like_pdf(path):
            return []

        try:
            reader = PdfReader(path)
        except (PdfReadError, OSError, ValueError):
            return _raw_scan(path)

        findings: list[Finding] = []

        if reader.is_encrypted:
            # Muchos PDF solo llevan contraseña de propietario (la de apertura está vacía): se
            # abren sin pedir nada y antes se dejaban sin revisar.
            try:
                opened = bool(reader.decrypt(""))
            except Exception:  # noqa: BLE001 -- cifrado no soportado o roto
                opened = False
            if not opened:
                findings.append(
                    Finding(
                        severity="info",
                        title="El PDF está cifrado/protegido con contraseña",
                    )
                )
                return findings  # sin la contraseña no se puede inspeccionar más
            findings.append(
                Finding(
                    severity="info",
                    title="El PDF está cifrado, pero se abre sin contraseña (solo restringe permisos)",
                )
            )

        try:
            catalog = reader.trailer["/Root"]
        except (KeyError, PdfReadError):
            return findings

        names = catalog.get("/Names", {}) if hasattr(catalog, "get") else {}

        if hasattr(names, "get") and "/JavaScript" in names:
            findings.append(
                Finding(
                    severity="high",
                    title="El PDF contiene JavaScript embebido",
                    detail="Revisar el JS antes de abrir el PDF en un lector que lo ejecute.",
                )
            )

        if hasattr(names, "get") and "/EmbeddedFiles" in names:
            findings.append(
                Finding(
                    severity="medium",
                    title="El PDF contiene ficheros embebidos",
                    detail="Extraer y revisar por separado antes de confiar en ellos.",
                )
            )

        if hasattr(catalog, "get") and catalog.get("/OpenAction") is not None:
            findings.append(
                Finding(
                    severity="medium",
                    title="El PDF tiene una acción de apertura automática (/OpenAction)",
                    detail="Se ejecuta algo en cuanto se abre el documento -- revisar qué hace.",
                )
            )

        actions: list[tuple[str, object]] = []
        try:
            if hasattr(catalog, "get"):
                actions += [("la apertura del documento", a) for a in _iter_actions(catalog.get("/OpenAction"))]
                actions += [("un evento del documento", a) for a in _additional_actions(catalog)]
                acroform = _resolve(catalog.get("/AcroForm"))
                if hasattr(acroform, "get") and "/Fields" in acroform:
                    for field in _form_fields(acroform["/Fields"]):
                        actions += [("un campo de formulario", a) for a in _additional_actions(field)]
            for number, page in enumerate(reader.pages, start=1):
                actions += [(f"la página {number}", a) for a in _additional_actions(page)]
                for annot_ref in page.get("/Annots", []) or []:
                    annot = _resolve(annot_ref)
                    if not hasattr(annot, "get"):
                        continue
                    where = f"un enlace o anotación de la página {number}"
                    actions += [(where, a) for a in _iter_actions(annot.get("/A"))]
                    actions += [(where, a) for a in _additional_actions(annot)]
        except (PdfReadError, KeyError, AttributeError, TypeError, ValueError):
            pass

        seen: set[tuple[str, str]] = set()
        for where, action in actions:
            kind = action.get("/S")
            if kind == "/URI":
                key = ("uri", str(action.get("/URI")))
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        Finding(
                            severity="low",
                            title=f"Enlace URI en el PDF: {action.get('/URI')}",
                            detail="No necesariamente malicioso -- revisar el destino.",
                        )
                    )
            elif kind in _RISKY_ACTIONS and (kind, where) not in seen:
                seen.add((kind, where))
                severity, what = _RISKY_ACTIONS[kind]
                findings.append(
                    Finding(
                        severity=severity,
                        title=f"Acción en {where}: {what}",
                        detail="Se ejecuta al abrir o al interactuar con el PDF -- revisar antes de abrirlo.",
                    )
                )

        return findings
