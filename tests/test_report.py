from filewhy.plugin import FileReport, Finding
from filewhy.report import to_console, to_json, worst_severity


def test_worst_severity_ninguno_sin_findings():
    assert worst_severity([FileReport(path="a.txt", findings=[])]) is None


def test_worst_severity_toma_el_mas_grave():
    reports = [
        FileReport(path="a.txt", findings=[Finding(severity="info", title="x")]),
        FileReport(path="b.txt", findings=[Finding(severity="high", title="y")]),
    ]
    assert worst_severity(reports) == "high"


def test_to_console_sin_hallazgos_mensaje_resumen():
    out = to_console([FileReport(path="a.txt", findings=[])])
    assert "0 hallazgo" in out


def test_to_console_con_hallazgos_sin_emojis():
    reports = [FileReport(path="a.exe", findings=[Finding(severity="high", title="Algo raro")])]
    out = to_console(reports)
    assert "[HIGH  ]" in out
    assert "a.exe" in out
    assert "🔧" not in out and "⚠" not in out


def test_to_json_valido():
    reports = [FileReport(path="a.txt", findings=[])]
    out = to_json(reports)
    assert '"path": "a.txt"' in out
