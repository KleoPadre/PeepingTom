from collections.abc import Iterator
from pathlib import Path

from typer.testing import CliRunner

from wispwire.capture import CaptureError
from wispwire.cli import app
from wispwire.diagnostics import DoctorReport
from wispwire.packets import PacketDetails, PacketSummary
from wispwire.sqlite_support import SqliteFeatureStatus
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
        sqlite_fts5=SqliteFeatureStatus(True, None),
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
        sqlite_fts5=SqliteFeatureStatus(
            False, "SQLite FTS5 trigram недоступен: токенизатор не найден"
        ),
    )
    monkeypatch.setattr("wispwire.cli.collect_doctor_report", lambda: report)

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "ОШИБКА" in result.stdout
    assert "SQLite FTS5 trigram: ОШИБКА" in result.stdout
    assert "Предупреждение: SQLite FTS5 trigram недоступен" in result.stdout
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


def fake_capture_session(started: list[str]):
    class FakeCaptureSession:
        def __init__(
            self, _dumpcap_path, _mergecap_path, interface, *, storage
        ) -> None:
            self.interface = interface
            self.storage = storage

        def start(self) -> None:
            started.append(self.interface)

    return FakeCaptureSession


def available_capture_tools(name: str) -> ToolStatus:
    return ToolStatus(name, Path(f"/opt/bin/{name}"), "4.4.0", None)


def test_capture_reports_missing_dumpcap_without_creating_session(monkeypatch) -> None:
    constructed: list[str] = []

    def unexpected_capture_session(*_args, **_kwargs) -> None:
        constructed.append("создана")

    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda name: ToolStatus(name, None, None, "не найден"),
    )
    monkeypatch.setattr("wispwire.cli.CaptureSession", unexpected_capture_session)

    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])

    assert result.exit_code == 1
    assert "dumpcap недоступен" in result.output
    assert constructed == []


def test_capture_reports_missing_mergecap_without_creating_session(monkeypatch) -> None:
    constructed: list[str] = []

    def inspect(name: str) -> ToolStatus:
        path = Path(f"/opt/bin/{name}") if name == "dumpcap" else None
        error = None if path is not None else "не найден"
        return ToolStatus(name, path, "4.4.0" if path else None, error)

    def unexpected_capture_session(*_args, **_kwargs) -> None:
        constructed.append("создана")

    monkeypatch.setattr("wispwire.cli.inspect_tool", inspect)
    monkeypatch.setattr("wispwire.cli.CaptureSession", unexpected_capture_session)

    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])

    assert result.exit_code == 1
    assert "mergecap недоступен" in result.output
    assert constructed == []


def test_capture_rejects_unknown_interface_without_creating_session(
    monkeypatch,
) -> None:
    constructed: list[str] = []

    def unexpected_capture_session(*_args, **_kwargs) -> None:
        constructed.append("создана")

    monkeypatch.setattr("wispwire.cli.inspect_tool", available_capture_tools)
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ("en0",))
    monkeypatch.setattr("wispwire.cli.CaptureSession", unexpected_capture_session)

    result = CliRunner().invoke(app, ["capture", "--iface", "en1"])

    assert result.exit_code == 2
    assert "Интерфейс en1 недоступен" in result.output
    assert constructed == []


def test_capture_starts_session_for_known_interface(monkeypatch) -> None:
    started: list[str] = []
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ("en0",))
    monkeypatch.setattr("wispwire.cli.CaptureSession", fake_capture_session(started))
    monkeypatch.setattr("wispwire.cli.inspect_tool", available_capture_tools)

    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])

    assert result.exit_code == 0
    assert started == ["en0"]
    assert "Live-захват запущен" in result.output


def test_capture_reports_session_start_error(monkeypatch) -> None:
    class FailingCaptureSession:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def start(self) -> None:
            raise CaptureError("нет прав")

    monkeypatch.setattr("wispwire.cli.inspect_tool", available_capture_tools)
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ("en0",))
    monkeypatch.setattr("wispwire.cli.CaptureSession", FailingCaptureSession)

    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])

    assert result.exit_code == 1
    assert "Не удалось запустить live-захват: нет прав" in result.output


def packet() -> PacketSummary:
    return PacketSummary(
        number=1,
        relative_time="0.000000",
        source="192.0.2.1",
        destination="192.0.2.53",
        protocol="DNS",
        length=74,
        info="Query",
    )


def fake_app(started: list[tuple[tuple[PacketSummary, ...], str]]):
    class FakeApp:
        def __init__(
            self,
            packets: tuple[PacketSummary, ...],
            source_name: str,
            _read_details,
        ) -> None:
            self.packets = packets
            self.source_name = source_name

        def run(self) -> None:
            started.append((self.packets, self.source_name))

    return FakeApp


def test_open_passes_capture_to_packet_details_reader(monkeypatch, tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    read_details_calls: list[tuple[Path, Path, int]] = []

    class FakeApp:
        def __init__(
            self,
            packets: tuple[PacketSummary, ...],
            _source_name: str,
            read_details,
        ) -> None:
            self._packets = packets
            self._read_details = read_details

        def run(self) -> None:
            self._read_details(self._packets[0])

    def fake_read_packet_details(
        received_capture_path: Path,
        tshark_path: Path,
        frame_number: int,
    ) -> PacketDetails:
        read_details_calls.append((received_capture_path, tshark_path, frame_number))
        return PacketDetails("Frame 1", "0000  aa")

    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/usr/bin/tshark"), "4.4.0", None),
    )
    monkeypatch.setattr(
        "wispwire.cli.iter_packet_summaries", lambda *_: iter([packet()])
    )
    monkeypatch.setattr("wispwire.cli.read_packet_details", fake_read_packet_details)
    monkeypatch.setattr("wispwire.cli.WispWireApp", FakeApp)

    result = CliRunner().invoke(app, ["open", str(capture_path)])

    assert result.exit_code == 0
    assert read_details_calls == [(capture_path, Path("/usr/bin/tshark"), 1)]


def test_open_starts_tui_with_read_only_packet_summaries(monkeypatch, tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    started: list[tuple[tuple[PacketSummary, ...], str]] = []
    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )
    monkeypatch.setattr(
        "wispwire.cli.iter_packet_summaries", lambda *_: iter([packet()])
    )
    monkeypatch.setattr("wispwire.cli.WispWireApp", fake_app(started))

    result = CliRunner().invoke(app, ["open", str(capture_path), "--limit", "10"])

    assert result.exit_code == 0
    assert started == [((packet(),), "capture.pcapng")]


def test_open_reports_empty_capture_without_starting_tui(monkeypatch, tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    started: list[tuple[tuple[PacketSummary, ...], str]] = []
    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )
    monkeypatch.setattr("wispwire.cli.iter_packet_summaries", lambda *_: iter(()))
    monkeypatch.setattr("wispwire.cli.WispWireApp", fake_app(started))

    result = CliRunner().invoke(app, ["open", str(capture_path)])

    assert result.exit_code == 0
    assert "Пакеты не найдены." in result.stdout
    assert started == []


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


def test_open_reports_tshark_read_error_after_received_packet(
    monkeypatch, tmp_path
) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )

    def packets_then_error(*_) -> Iterator[PacketSummary]:
        yield packet()
        raise TsharkReadError("Повреждённый захват")

    monkeypatch.setattr("wispwire.cli.iter_packet_summaries", packets_then_error)

    result = CliRunner().invoke(app, ["open", str(capture_path)])

    assert result.exit_code == 1
    assert "Не удалось прочитать захват: Повреждённый захват" in result.stdout


def test_open_rejects_zero_limit(tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()

    result = CliRunner().invoke(app, ["open", str(capture_path), "--limit", "0"])

    assert result.exit_code == 2
    assert "Invalid value" in result.output
