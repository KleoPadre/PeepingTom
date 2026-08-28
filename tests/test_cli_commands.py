from pathlib import Path

from typer.testing import CliRunner

from wispwire.cli import app
from wispwire.diagnostics import DoctorReport
from wispwire.packets import PacketSummary
from wispwire.tshark import TsharkReadError
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


def test_doctor_prints_error_status_and_capture_warning(monkeypatch) -> None:
    report = DoctorReport(
        python_version="3.11.9",
        wispwire_version="0.1.0",
        tools=(ToolStatus("tshark", None, None, "утилита не найдена в PATH"),),
        interfaces=(),
        capture_warning="live-захват недоступен: установите dumpcap",
    )
    monkeypatch.setattr("wispwire.cli.collect_doctor_report", lambda: report)

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "ОШИБКА" in result.stdout
    assert "Предупреждение: live-захват недоступен: установите dumpcap" in result.stdout


def test_interfaces_reports_no_available_interfaces(monkeypatch) -> None:
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ())

    result = CliRunner().invoke(app, ["interfaces"])

    assert result.exit_code == 0
    assert "Интерфейсы не найдены" in result.stdout


def test_interfaces_prints_numbered_available_interfaces(monkeypatch) -> None:
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ("en0", "lo0"))

    result = CliRunner().invoke(app, ["interfaces"])

    assert result.exit_code == 0
    assert "1. en0" in result.stdout
    assert "2. lo0" in result.stdout


def test_open_prints_packet_table(monkeypatch, tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    packet = PacketSummary(
        number=1,
        relative_time="0.000000",
        source="192.0.2.1",
        destination="192.0.2.53",
        protocol="DNS",
        length=74,
        info="Query",
    )
    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )
    monkeypatch.setattr("wispwire.cli.iter_packet_summaries", lambda *_: iter([packet]))

    result = CliRunner().invoke(app, ["open", str(capture_path), "--limit", "10"])

    assert result.exit_code == 0
    assert "DNS" in result.stdout
    assert "Query" in result.stdout


def test_open_reports_empty_capture(monkeypatch, tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )
    monkeypatch.setattr("wispwire.cli.iter_packet_summaries", lambda *_: iter(()))

    result = CliRunner().invoke(app, ["open", str(capture_path)])

    assert result.exit_code == 0
    assert "Пакеты не найдены." in result.stdout


def test_open_rejects_missing_capture_path() -> None:
    result = CliRunner().invoke(app, ["open", "missing.pcapng"])

    assert result.exit_code == 2
    assert "Файл захвата не найден" in result.stdout


def test_open_rejects_directory_instead_of_capture(tmp_path) -> None:
    result = CliRunner().invoke(app, ["open", str(tmp_path)])

    assert result.exit_code == 2
    assert "Ожидается файл захвата" in result.stdout


def test_open_reports_missing_tshark(monkeypatch, tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", None, None, "утилита не найдена в PATH"),
    )

    result = CliRunner().invoke(app, ["open", str(capture_path)])

    assert result.exit_code == 1
    assert "wispwire doctor" in result.stdout


def test_open_reports_tshark_read_error_without_traceback(
    monkeypatch, tmp_path
) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )

    def raise_read_error(*_) -> None:
        raise TsharkReadError("Повреждённый захват")

    monkeypatch.setattr("wispwire.cli.iter_packet_summaries", raise_read_error)

    result = CliRunner().invoke(app, ["open", str(capture_path)])

    assert result.exit_code == 1
    assert "Повреждённый захват" in result.stdout
    assert "Traceback" not in result.stdout


def test_open_rejects_zero_limit(tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()

    result = CliRunner().invoke(app, ["open", str(capture_path), "--limit", "0"])

    assert result.exit_code == 2
    assert "Invalid value" in result.output
