from filewhy.cli import main


def test_scan_fichero_limpio_exit_0(workdir, capsys):
    p = workdir / "a.txt"
    p.write_text("hola")
    rc = main(["scan", str(p), "--fail-on", "high"])
    assert rc == 0


def test_scan_fichero_disfrazado_exit_1(workdir, capsys):
    p = workdir / "foto.jpg"
    p.write_bytes(b"MZ\x90\x00\x03")
    rc = main(["scan", str(p), "--fail-on", "high"])
    assert rc == 1


def test_scan_json(workdir, capsys):
    p = workdir / "a.txt"
    p.write_text("hola")
    main(["scan", str(p), "--json"])
    out = capsys.readouterr().out
    assert '"path"' in out


def test_list_checks(capsys):
    main(["list-checks"])
    out = capsys.readouterr().out
    assert "file_identity" in out
    assert "archive_risk" in out
    assert "pdf_risk" in out


def test_scan_ruta_inexistente_sale_2(workdir, capsys):
    assert main(["scan", str(workdir / "no-existe")]) == 2
    assert "no existe" in capsys.readouterr().err


def test_scan_check_desconocido_sale_2(workdir, capsys):
    assert main(["scan", str(workdir), "--only", "typo"]) == 2


def test_check_que_revienta_sale_2(workdir, monkeypatch, capsys):
    from filewhy import runner

    class Roto:
        name = "roto"

        def run(self, path):
            raise RuntimeError("boom")

    (workdir / "a.txt").write_text("x")
    monkeypatch.setattr(runner, "discover_checks", lambda: {"roto": Roto})
    assert main(["scan", str(workdir), "--fail-on", "high"]) == 2
    assert "análisis incompleto" in capsys.readouterr().err
