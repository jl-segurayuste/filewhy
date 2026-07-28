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
