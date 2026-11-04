from filewhy.checks.file_identity import FileIdentityCheck, detect_real_type


def test_detect_real_type_pdf(workdir):
    p = workdir / "a.pdf"
    p.write_bytes(b"%PDF-1.4\n...")
    assert detect_real_type(p) == "PDF"


def test_detect_real_type_zip(workdir):
    p = workdir / "a.zip"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 20)
    assert detect_real_type(p) == "ZIP"


def test_detect_real_type_pe(workdir):
    p = workdir / "a.bin"
    p.write_bytes(b"MZ\x90\x00\x03")
    assert detect_real_type(p) == "PE/EXE (Windows)"


def test_detect_real_type_desconocido(workdir):
    p = workdir / "a.txt"
    p.write_text("hola mundo")
    assert detect_real_type(p) is None


def test_extension_coincide_no_hay_hallazgo(workdir):
    p = workdir / "real.pdf"
    p.write_bytes(b"%PDF-1.4\n...")
    assert FileIdentityCheck().run(p) == []


def test_extension_no_coincide_se_marca(workdir):
    p = workdir / "foto.jpg"
    p.write_bytes(b"MZ\x90\x00\x03")  # PE disfrazado de .jpg
    findings = FileIdentityCheck().run(p)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "PE/EXE" in findings[0].title


def test_extension_no_vigilada_no_se_marca(workdir):
    p = workdir / "notas.md"
    p.write_bytes(b"MZ\x90\x00\x03")
    assert FileIdentityCheck().run(p) == []


def test_contenido_no_reconocido_no_se_marca(workdir):
    p = workdir / "raro.pdf"
    p.write_text("esto no es realmente un pdf")
    assert FileIdentityCheck().run(p) == []


def test_ole_rar_7z_disfrazados_se_marcan(workdir):
    casos = {
        "factura.pdf": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1resto",
        "foto.jpg": b"Rar!\x1a\x07\x00resto",
        "doc.docx": b"7z\xbc\xaf\x27\x1cresto",
    }
    for name, data in casos.items():
        p = workdir / name
        p.write_bytes(data)
        assert len(FileIdentityCheck().run(p)) == 1, name


def test_ole_con_extension_de_office_antiguo_no_se_marca(workdir):
    p = workdir / "informe.doc"
    p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1resto")
    assert FileIdentityCheck().run(p) == []
