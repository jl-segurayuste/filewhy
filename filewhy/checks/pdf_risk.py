from __future__ import annotations

from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from filewhy.plugin import Finding


class PdfRiskCheck:
    """Señales de riesgo en PDF: JavaScript embebido, acción de apertura automática,
    ficheros embebidos, y si está cifrado. Solo inspecciona la estructura de objetos
    del PDF -- nunca ejecuta ningún JavaScript ni abre ningún fichero embebido.
    """

    name = "pdf_risk"

    def run(self, path: Path) -> list[Finding]:
        if path.suffix.lower() != ".pdf":
            return []

        try:
            reader = PdfReader(path)
        except (PdfReadError, OSError, ValueError):
            return []

        findings: list[Finding] = []

        if reader.is_encrypted:
            findings.append(
                Finding(
                    severity="info",
                    title="El PDF está cifrado/protegido con contraseña",
                )
            )
            return findings  # sin la contraseña no se puede inspeccionar más

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

        try:
            for page in reader.pages:
                for annot_ref in page.get("/Annots", []) or []:
                    annot = annot_ref.get_object()
                    action = annot.get("/A") if hasattr(annot, "get") else None
                    if action and hasattr(action, "get") and action.get("/S") == "/URI":
                        findings.append(
                            Finding(
                                severity="low",
                                title=f"Enlace URI en el PDF: {action.get('/URI')}",
                                detail="No necesariamente malicioso -- revisar el destino.",
                            )
                        )
        except (PdfReadError, KeyError, AttributeError):
            pass

        return findings
