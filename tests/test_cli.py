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
