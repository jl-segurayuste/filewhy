from filewhy.runner import analyze_file, analyze_path, discover_checks


def test_discover_checks_incluye_los_builtin():
    checks = discover_checks()
    expected = {"file_identity", "archive_risk", "pdf_risk"}
    assert expected <= set(checks)


def test_analyze_file_fichero_limpio_sin_hallazgos(workdir):
    p = workdir / "notas.txt"
    p.write_text("hola")
    report = analyze_file(p)
    assert report.path == str(p)
    assert report.findings == []


def test_analyze_file_disfrazado_marca_hallazgo(workdir):
    p = workdir / "foto.jpg"
    p.write_bytes(b"MZ\x90\x00\x03")
    report = analyze_file(p)
    assert len(report.findings) == 1


def test_analyze_file_only_filtra_checks(workdir):
    p = workdir / "foto.jpg"
    p.write_bytes(b"MZ\x90\x00\x03")
    report = analyze_file(p, only={"archive_risk"})
    assert report.findings == []  # el hallazgo era de file_identity, no de archive_risk


def test_analyze_path_directorio_recorre_todo(workdir):
    (workdir / "a.txt").write_text("hola")
    (workdir / "sub").mkdir()
    (workdir / "sub" / "b.jpg").write_bytes(b"MZ\x90\x00\x03")
    reports = analyze_path(workdir)
    assert len(reports) == 2
    disguised = next(r for r in reports if r.path.endswith("b.jpg"))
    assert len(disguised.findings) == 1


def test_analyze_path_un_solo_fichero(workdir):
    p = workdir / "a.txt"
    p.write_text("hola")
    reports = analyze_path(p)
    assert len(reports) == 1


def test_analyze_file_check_roto_no_rompe_el_resto(workdir, monkeypatch):
    import filewhy.runner as runner_module

    class BrokenCheck:
        name = "broken"

        def run(self, path):
            raise RuntimeError("boom")

    monkeypatch.setattr(runner_module, "discover_checks", lambda: {"broken": BrokenCheck})
    p = workdir / "a.txt"
    p.write_text("hola")
    report = analyze_file(p)
    assert len(report.findings) == 1
    assert "boom" in report.findings[0].title
