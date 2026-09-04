from datetime import datetime
from pathlib import Path

from typer.testing import CliRunner

from wispwire.capture import CaptureError
from wispwire.cli import app
from wispwire.diagnostics import DoctorReport
from wispwire.file_source import PacketQuery, PacketQueryResult
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


def fake_live_components(
    monkeypatch,
    events: list[str],
    *,
    result: Path | None = None,
    error: CaptureError | None = None,
) -> None:
    class FakeCaptureSession:
        def __init__(self, dumpcap_path, mergecap_path, interface, *, storage) -> None:
            events.append(
                f"session:{dumpcap_path.name}:{mergecap_path.name}:{interface}"
            )

    class FakeLivePacketSource:
        def __init__(self, tshark_path) -> None:
            events.append(f"source:{tshark_path.name}")

        def query(self, _query):
            raise AssertionError("запрос выполняет только live-TUI")

        def read_details(self, _number):
            raise AssertionError("детали читает только live-TUI")

    class FakeLiveCaptureController:
        def __init__(self, capture, source, *, destination_factory) -> None:
            events.append("controller")

    class FakeLiveCaptureApp:
        def __init__(
            self,
            interface,
            controller,
            query_packets,
            read_details,
            *,
            display_filter_fields=(),
            available_interfaces=(),
            runtime_factory=None,
        ) -> None:
            if display_filter_fields:
                events.append(f"fields:{','.join(display_filter_fields)}")
            if available_interfaces:
                events.append(f"interfaces:{','.join(available_interfaces)}")
            if runtime_factory is not None:
                events.append("runtime-factory")
            events.append(f"app:{interface}")

        def run(self) -> Path | None:
            events.append("run")
            if error is not None:
                raise error
            return result

    monkeypatch.setattr("wispwire.cli.CaptureSession", FakeCaptureSession)
    monkeypatch.setattr("wispwire.cli.LivePacketSource", FakeLivePacketSource)
    monkeypatch.setattr("wispwire.cli.LiveCaptureController", FakeLiveCaptureController)
    monkeypatch.setattr("wispwire.cli.LiveCaptureApp", FakeLiveCaptureApp)


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
    monkeypatch.setattr(
        "wispwire.cli.LiveCaptureController",
        unexpected_capture_session,
        raising=False,
    )
    monkeypatch.setattr(
        "wispwire.cli.LiveCaptureApp", unexpected_capture_session, raising=False
    )

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
    monkeypatch.setattr(
        "wispwire.cli.LiveCaptureController",
        unexpected_capture_session,
        raising=False,
    )
    monkeypatch.setattr(
        "wispwire.cli.LiveCaptureApp", unexpected_capture_session, raising=False
    )

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
    monkeypatch.setattr(
        "wispwire.cli.LiveCaptureController",
        unexpected_capture_session,
        raising=False,
    )
    monkeypatch.setattr(
        "wispwire.cli.LiveCaptureApp", unexpected_capture_session, raising=False
    )

    result = CliRunner().invoke(app, ["capture", "--iface", "en1"])

    assert result.exit_code == 2
    assert "Интерфейс en1 недоступен" in result.output
    assert constructed == []


def test_capture_reports_missing_tshark_without_creating_session(monkeypatch) -> None:
    constructed: list[str] = []

    def inspect(name: str) -> ToolStatus:
        if name == "tshark":
            return ToolStatus(name, None, None, "не найден")
        return available_capture_tools(name)

    def unexpected_component(*_args, **_kwargs) -> None:
        constructed.append("создан")

    monkeypatch.setattr("wispwire.cli.inspect_tool", inspect)
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ("en0",))
    monkeypatch.setattr("wispwire.cli.CaptureSession", unexpected_component)
    monkeypatch.setattr("wispwire.cli.LiveCaptureController", unexpected_component)
    monkeypatch.setattr("wispwire.cli.LiveCaptureApp", unexpected_component)

    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])

    assert result.exit_code == 1
    assert "TShark недоступен" in result.output
    assert constructed == []


def test_capture_opens_live_tui_and_passes_saved_result_to_file_tui(
    monkeypatch, tmp_path
) -> None:
    events: list[str] = []
    saved = tmp_path / "capture_2026-09-03_12-00-00.pcapng"
    saved.touch()
    opened: list[Path] = []
    fake_live_components(monkeypatch, events, result=saved)
    monkeypatch.setattr("wispwire.cli.inspect_tool", available_capture_tools)
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ("en0",))
    monkeypatch.setattr(
        "wispwire.cli.read_display_filter_fields", lambda _path: ("tcp", "tcp.port")
    )
    monkeypatch.setattr(
        "wispwire.cli._open_capture_in_tui", opened.append, raising=False
    )

    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])

    assert result.exit_code == 0
    assert events == [
        "session:dumpcap:mergecap:en0",
        "source:tshark",
        "controller",
        "fields:tcp,tcp.port",
        "interfaces:en0",
        "runtime-factory",
        "app:en0",
        "run",
    ]
    assert opened == [saved]


def test_capture_does_not_open_file_tui_after_quit(monkeypatch) -> None:
    events: list[str] = []
    opened: list[Path] = []
    fake_live_components(monkeypatch, events, result=None)
    monkeypatch.setattr("wispwire.cli.inspect_tool", available_capture_tools)
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ("en0",))
    monkeypatch.setattr(
        "wispwire.cli._open_capture_in_tui", opened.append, raising=False
    )

    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])

    assert result.exit_code == 0
    assert events[-2:] == ["app:en0", "run"]
    assert opened == []


def test_capture_reports_live_error_without_traceback(monkeypatch) -> None:
    events: list[str] = []
    fake_live_components(
        monkeypatch, events, error=CaptureError("dumpcap потерял интерфейс")
    )
    monkeypatch.setattr("wispwire.cli.inspect_tool", available_capture_tools)
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ("en0",))

    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])

    assert result.exit_code == 1
    assert "dumpcap потерял интерфейс" in result.output
    assert "Traceback" not in result.output


def test_capture_reports_controller_close_error_without_traceback(monkeypatch) -> None:
    events: list[str] = []
    fake_live_components(
        monkeypatch,
        events,
        error=CaptureError("не удалось безопасно закрыть live-захват"),
    )
    monkeypatch.setattr("wispwire.cli.inspect_tool", available_capture_tools)
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ("en0",))

    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])

    assert result.exit_code == 1
    assert "не удалось безопасно закрыть live-захват" in result.output
    assert "Traceback" not in result.output


def test_capture_destination_creates_catalog_and_uses_next_free_suffix(
    monkeypatch, tmp_path
) -> None:
    from wispwire import cli

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 9, 3, 12, 0, 0)

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(cli, "datetime", FixedDateTime, raising=False)
    catalog = tmp_path / "WispWire" / "Captures"
    first = cli._capture_destination()
    first.touch()
    second = cli._capture_destination()
    second.touch()

    destination = cli._capture_destination()

    assert first == catalog / "capture_2026-09-03_12-00-00.pcapng"
    assert second == catalog / "capture_2026-09-03_12-00-00-2.pcapng"
    assert destination == catalog / "capture_2026-09-03_12-00-00-3.pcapng"
    assert catalog.is_dir()
    assert not destination.exists()


def test_capture_help_describes_live_tui() -> None:
    result = CliRunner().invoke(app, ["capture", "--help"])

    assert result.exit_code == 0
    assert "live-TUI" in result.output


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
            **_kwargs,
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
            **_kwargs,
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

    class FakeSource:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def load(self, _limit: int) -> tuple[PacketSummary, ...]:
            return (packet(),)

        def query(self, _query: PacketQuery) -> PacketQueryResult:
            return PacketQueryResult((packet(),), None)

        def close(self) -> None:
            pass

    monkeypatch.setattr("wispwire.cli.FilePacketSource", FakeSource)
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

    class FakeSource:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def load(self, _limit: int) -> tuple[PacketSummary, ...]:
            return (packet(),)

        def query(self, _query: PacketQuery) -> PacketQueryResult:
            return PacketQueryResult((packet(),), None)

        def close(self) -> None:
            pass

    monkeypatch.setattr("wispwire.cli.FilePacketSource", FakeSource)
    monkeypatch.setattr("wispwire.cli.WispWireApp", fake_app(started))

    result = CliRunner().invoke(app, ["open", str(capture_path), "--limit", "10"])

    assert result.exit_code == 0
    assert started == [((packet(),), "capture.pcapng")]


def test_open_passes_initial_display_filter_to_tui(monkeypatch, tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    started: list[str] = []

    class FakeSource:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def load(self, _limit: int) -> tuple[PacketSummary, ...]:
            return (packet(),)

        def query(self, _query: PacketQuery) -> PacketQueryResult:
            return PacketQueryResult((packet(),), None)

        def close(self) -> None:
            pass

    class FakeApp:
        def __init__(self, *_args, initial_filter: str = "", **_kwargs) -> None:
            started.append(initial_filter)

        def run(self) -> None:
            pass

    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )
    monkeypatch.setattr("wispwire.cli.FilePacketSource", FakeSource)
    monkeypatch.setattr("wispwire.cli.WispWireApp", FakeApp)

    result = CliRunner().invoke(app, ["open", str(capture_path), "--filter", "udp"])

    assert result.exit_code == 0
    assert started == ["udp"]


def test_open_closes_file_packet_source_after_tui_exit(monkeypatch, tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    events: list[str] = []

    class FakeSource:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def load(self, _limit: int) -> tuple[PacketSummary, ...]:
            return (packet(),)

        def query(self, _query: PacketQuery) -> PacketQueryResult:
            return PacketQueryResult((packet(),), None)

        def close(self) -> None:
            events.append("close")

    class FakeApp:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self) -> None:
            events.append("run")

    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )
    monkeypatch.setattr("wispwire.cli.FilePacketSource", FakeSource)
    monkeypatch.setattr("wispwire.cli.WispWireApp", FakeApp)

    result = CliRunner().invoke(app, ["open", str(capture_path)])

    assert result.exit_code == 0
    assert events == ["run", "close"]


def test_open_reports_empty_capture_without_starting_tui(monkeypatch, tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    started: list[tuple[tuple[PacketSummary, ...], str]] = []
    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )

    class FakeSource:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def load(self, _limit: int) -> tuple[PacketSummary, ...]:
            return ()

        def query(self, _query: PacketQuery) -> PacketQueryResult:
            return PacketQueryResult((), None)

        def close(self) -> None:
            pass

    monkeypatch.setattr("wispwire.cli.FilePacketSource", FakeSource)
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

    class FakeSource:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def load(self, _limit: int) -> tuple[PacketSummary, ...]:
            raise TsharkReadError("Повреждённый захват")

        def close(self) -> None:
            pass

    monkeypatch.setattr("wispwire.cli.FilePacketSource", FakeSource)

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

    class FakeSource:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def load(self, _limit: int) -> tuple[PacketSummary, ...]:
            raise TsharkReadError("Повреждённый захват")

        def close(self) -> None:
            pass

    monkeypatch.setattr("wispwire.cli.FilePacketSource", FakeSource)

    result = CliRunner().invoke(app, ["open", str(capture_path)])

    assert result.exit_code == 1
    assert "Не удалось прочитать захват: Повреждённый захват" in result.stdout


def test_open_rejects_zero_limit(tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()

    result = CliRunner().invoke(app, ["open", str(capture_path), "--limit", "0"])

    assert result.exit_code == 2
    assert "Invalid value" in result.output
