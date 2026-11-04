from pypdf import PdfWriter

try:
    from pypdf.actions import JavaScript
except ImportError:  # pypdf < 6
    JavaScript = None

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
    if JavaScript is not None:  # pypdf >= 6: add_js desaparece en pypdf 7
        writer.add_open_action(JavaScript("app.alert('hola');"))
    else:
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


def _js_writer():
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    if JavaScript is not None:
        writer.add_open_action(JavaScript("app.alert(1)"))
    else:  # pypdf < 6
        writer.add_js("app.alert(1)")
    return writer


def test_launch_en_un_enlace_se_detecta(workdir):
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        NumberObject,
        TextStringObject,
    )

    writer = PdfWriter()
    page = writer.add_blank_page(width=200, height=200)
    action = DictionaryObject({NameObject("/S"): NameObject("/Launch"), NameObject("/F"): TextStringObject("cmd.exe")})
    annot = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4), NameObject("/A"): action,
    })
    page[NameObject("/Annots")] = ArrayObject([writer._add_object(annot)])
    p = workdir / "launch.pdf"
    with open(p, "wb") as f:
        writer.write(f)
    assert any(f.severity == "high" and "/Launch" in f.title for f in PdfRiskCheck().run(p))


def test_cifrado_sin_contrasena_de_apertura_se_revisa(workdir):
    writer = _js_writer()
    writer.encrypt(user_password="", owner_password="propietario")
    p = workdir / "cifrado.pdf"
    with open(p, "wb") as f:
        writer.write(f)
    assert any(f.severity == "high" for f in PdfRiskCheck().run(p))


def test_cifrado_con_contrasena_no_se_puede_revisar(workdir):
    writer = _js_writer()
    writer.encrypt(user_password="usuario", owner_password="propietario")
    p = workdir / "cerrado.pdf"
    with open(p, "wb") as f:
        writer.write(f)
    assert [f.severity for f in PdfRiskCheck().run(p)] == ["info"]


def test_pdf_sin_extension_se_reconoce_por_la_firma(workdir):
    p = workdir / "factura"
    with open(p, "wb") as f:
        _js_writer().write(f)
    assert any(f.severity == "high" for f in PdfRiskCheck().run(p))


def test_pdf_malformado_con_javascript_se_detecta_por_bytes(workdir):
    # Sin xref ni startxref: pypdf no lo lee, pero un lector lo repara y lo abre.
    p = workdir / "contrato.pdf"
    p.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /S /J#61vaScript /JS (app.alert(1);) >>\nendobj\n%%EOF\n"
    )
    titles = {f.title for f in PdfRiskCheck().run(p)}
    assert "El PDF contiene JavaScript" in titles
    assert "El PDF ejecuta una acción al abrirse (/OpenAction)" in titles
    assert any(t.startswith("PDF malformado") for t in titles)


def test_ejecutable_con_extension_pdf_no_se_revisa_por_bytes(workdir):
    p = workdir / "factura.pdf"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 60 + b"/JavaScript")
    assert PdfRiskCheck().run(p) == []


def test_codigo_que_menciona_pdf_no_se_revisa_por_bytes(workdir):
    # Un .py/.pyc con «%PDF-» y nombres como /JavaScript en el código no es un PDF.
    p = workdir / "pdf_risk.cpython-312.pyc"
    p.write_bytes(b'\x00\x00 b"%PDF-" "/JavaScript" "/Launch" "/OpenAction"')
    assert PdfRiskCheck().run(p) == []
