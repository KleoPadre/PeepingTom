from pathlib import Path

from typer.testing import CliRunner

from wispwire.cli import app
from wispwire.diagnostics import DoctorReport
from wispwire.wireshark import ToolStatus


def fake_report() -> DoctorReport:
    return DoctorReport(
        python_version="3.11.9",
        wispwire_version="0.1.0",
        tools=(
            ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
            ToolStatus("dumpcap", Path("/opt/bin/dumpcap"), "4.4.0", None),
            ToolStatus("mergecap", Path("/opt/bin/mergecap"), "4.4.0", None),
        ),
        interfaces=("en0", "lo0"),
        capture_warning=None,
    )


def test_doctor_prints_tool_statuses(monkeypatch) -> None:
    monkeypatch.setattr("wispwire.cli.collect_doctor_report", fake_report)

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "tshark" in result.stdout
    assert "OK" in result.stdout


def test_interfaces_reports_no_available_interfaces(monkeypatch) -> None:
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ())

    result = CliRunner().invoke(app, ["interfaces"])

    assert result.exit_code == 0
    assert "Интерфейсы не найдены" in result.stdout
