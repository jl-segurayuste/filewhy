import zipfile

from filewhy.checks.archive_risk import ArchiveRiskCheck


def _make_zip(path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in members.items():
            zf.writestr(name, content)


def test_no_es_zip_no_hay_hallazgos(workdir):
    p = workdir / "notas.txt"
    p.write_text("hola")
    assert ArchiveRiskCheck().run(p) == []


def test_zip_normal_sin_hallazgos(workdir):
    p = workdir / "normal.zip"
    _make_zip(p, {"readme.txt": b"hola mundo"})
    assert ArchiveRiskCheck().run(p) == []


def test_zip_slip_se_detecta(workdir):
    p = workdir / "malicioso.zip"
    _make_zip(p, {"../../etc/passwd": b"x"})
    findings = ArchiveRiskCheck().run(p)
    assert any("traversal" in f.title.lower() for f in findings)
    assert any(f.severity == "high" for f in findings)


def test_zip_slip_con_backslash_se_detecta(workdir):
    # Bug real encontrado 2026-08-09: el nombre del miembro se comprobaba con
    # Path(name).parts, que en Linux solo separa por "/" -- un ZIP creado (o
    # manipulado a mano) con "\" como separador, como haría un atacante para
    # evadir un check ingenuo, pasaba desapercibido pese a ser el mismo
    # ataque de zip-slip.
    p = workdir / "malicioso_backslash.zip"
    _make_zip(p, {"..\\..\\evil.exe": b"x"})
    findings = ArchiveRiskCheck().run(p)
    assert any("traversal" in f.title.lower() for f in findings)
    assert any(f.severity == "high" for f in findings)


def test_ruta_absoluta_con_unidad_windows_se_detecta(workdir):
    # Bug real encontrado 2026-08-09: solo se comprobaba name.startswith("/"),
    # así que una ruta absoluta de Windows tipo "C:\Windows\..." (que
    # sobrescribiría un fichero fuera del directorio destino igual que un "/"
    # inicial) no se detectaba como traversal.
    p = workdir / "malicioso_unidad.zip"
    _make_zip(p, {"C:\\Windows\\System32\\evil.dll": b"x"})
    findings = ArchiveRiskCheck().run(p)
    assert any("traversal" in f.title.lower() for f in findings)
    assert any(f.severity == "high" for f in findings)


def test_miembro_ejecutable_se_detecta(workdir):
    p = workdir / "con_exe.zip"
    _make_zip(p, {"payload.exe": b"MZ fake exe content"})
    findings = ArchiveRiskCheck().run(p)
    assert any("ejecutable" in f.title.lower() for f in findings)


def test_ratio_compresion_sospechoso_se_detecta(workdir):
    p = workdir / "bomba.zip"
    # 11 MB de ceros comprime brutalmente -- ratio muy alto
    _make_zip(p, {"bomb.bin": b"\x00" * (11 * 1024 * 1024)})
    findings = ArchiveRiskCheck().run(p)
    assert any("compresión" in f.title.lower() or "ratio" in f.title.lower() for f in findings)


def test_zip_pequeno_no_marca_ratio(workdir):
    p = workdir / "pequeno.zip"
    _make_zip(p, {"tiny.bin": b"\x00" * 1000})
    findings = ArchiveRiskCheck().run(p)
    assert not any("ratio" in f.title.lower() for f in findings)


def _titles(path):
    return [f.title for f in ArchiveRiskCheck().run(path)]


def test_script_en_la_raiz_y_accesos_directos(workdir):
    p = workdir / "adjunto.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("factura.js", "x")
        zf.writestr("web/app.js", "x")          # dentro de una carpeta: normal
        zf.writestr("doc.lnk", "x")
    titles = _titles(p)
    assert any("factura.js" in t for t in titles)
    assert not any("web/app.js" in t for t in titles)
    assert any("doc.lnk" in t for t in titles)


def test_macros_vba_y_objetos_ole(workdir):
    p = workdir / "informe.docx"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("word/vbaProject.bin", "x")
        zf.writestr("word/embeddings/oleObject1.bin", "x")
    titles = _titles(p)
    assert any("macros VBA" in t for t in titles) and any("OLE" in t for t in titles)


def test_enlace_simbolico(workdir):
    import stat

    p = workdir / "link.zip"
    with zipfile.ZipFile(p, "w") as zf:
        info = zipfile.ZipInfo("enlace")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
    assert any("simbólico" in t for t in _titles(p))


def test_miembro_cifrado(workdir):
    p = workdir / "cifrado.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("secreto.txt", "x")
    raw = bytearray(p.read_bytes())
    # zipfile no escribe ZIP cifrados: se activa el bit 0 de los flags en la cabecera local
    # (desplazamiento 6) y en la del directorio central (desplazamiento 8)
    raw[raw.index(b"PK\x03\x04") + 6] |= 0x1
    raw[raw.index(b"PK\x01\x02") + 8] |= 0x1
    p.write_bytes(bytes(raw))
    assert any("cifrado" in t for t in _titles(p))
