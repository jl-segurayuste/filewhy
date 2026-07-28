from pypdf import PdfWriter

from filewhy.checks.pdf_risk import PdfRiskCheck


def _write_pdf(path, *, add_page=True):
    writer = PdfWriter()
    if add_page:
        writer.add_blank_page(width=200, height=200)
    with open(path, "wb") as f:
        writer.write(f)
    return writer


def test_no_es_pdf_no_hay_hallazgos(workdir):
    p = workdir / "notas.txt"
    p.write_text("hola")
    assert PdfRiskCheck().run(p) == []


def test_pdf_normal_sin_hallazgos(workdir):
    p = workdir / "normal.pdf"
    _write_pdf(p)
    assert PdfRiskCheck().run(p) == []


def test_pdf_con_javascript_se_detecta(workdir):
    p = workdir / "con_js.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.add_js("app.alert('hola');")
    with open(p, "wb") as f:
        writer.write(f)

    findings = PdfRiskCheck().run(p)
    assert any("javascript" in f.title.lower() for f in findings)
    assert any(f.severity == "high" for f in findings)


def test_pdf_cifrado_se_detecta(workdir):
    p = workdir / "cifrado.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.encrypt("secreto123")
    with open(p, "wb") as f:
        writer.write(f)

    findings = PdfRiskCheck().run(p)
    assert any("cifrado" in f.title.lower() for f in findings)


def test_pdf_invalido_no_rompe(workdir):
    p = workdir / "roto.pdf"
    p.write_bytes(b"%PDF-1.4\nesto esta roto y no es un pdf valido")
    # no debe lanzar excepcion, solo devolver lo que pueda (o nada)
    PdfRiskCheck().run(p)
