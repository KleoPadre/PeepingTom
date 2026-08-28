from pathlib import Path
from subprocess import CompletedProcess

from wispwire.diagnostics import collect_doctor_report, list_interfaces
from wispwire.wireshark import ToolStatus


def fake_interfaces_run(*_: object, **__: object) -> CompletedProcess[str]:
    return CompletedProcess(
        ["dumpcap", "-D"],
        0,
        "1. en0 (Wi-Fi)\n2. lo0 (Loopback)\n",
        "",
    )


def test_list_interfaces_parses_dumpcap_output() -> None:
    assert list_interfaces(run=fake_interfaces_run) == ("en0", "lo0")


def test_list_interfaces_returns_empty_tuple_when_dumpcap_fails() -> None:
    result = list_interfaces(
        run=lambda *_args, **_kwargs: CompletedProcess(["dumpcap", "-D"], 1, "", "")
    )

    assert result == ()


def test_list_interfaces_returns_empty_tuple_when_dumpcap_cannot_start() -> None:
    def failing_run(*_: object, **__: object) -> CompletedProcess[str]:
        raise OSError("нет доступа")

    assert list_interfaces(run=failing_run) == ()


def test_doctor_warns_when_capture_tools_are_missing() -> None:
    def fake_missing_inspect(name: str) -> ToolStatus:
        return ToolStatus(name, None, None, "утилита не найдена в PATH")

    report = collect_doctor_report(
        inspect=fake_missing_inspect,
        interfaces=lambda: (),
    )

    assert report.capture_warning == "live-захват недоступен: установите dumpcap"


def test_doctor_collects_tools_and_interfaces_when_dumpcap_is_available() -> None:
    def fake_inspect(name: str) -> ToolStatus:
        return ToolStatus(name, Path(f"/opt/bin/{name}"), "4.4.0", None)

    report = collect_doctor_report(
        inspect=fake_inspect,
        interfaces=lambda: ("en0", "lo0"),
    )

    assert tuple(tool.name for tool in report.tools) == (
        "tshark",
        "dumpcap",
        "mergecap",
    )
    assert report.interfaces == ("en0", "lo0")
    assert report.capture_warning is None
    assert report.python_version
    assert report.wispwire_version == "0.1.0"


def test_doctor_does_not_list_interfaces_without_working_dumpcap() -> None:
    called = False

    def fake_inspect(name: str) -> ToolStatus:
        if name == "dumpcap":
            return ToolStatus(
                name, Path("/opt/bin/dumpcap"), None, "не удалось запустить"
            )
        return ToolStatus(name, Path(f"/opt/bin/{name}"), "4.4.0", None)

    def interfaces() -> tuple[str, ...]:
        nonlocal called
        called = True
        return ("en0",)

    report = collect_doctor_report(inspect=fake_inspect, interfaces=interfaces)

    assert called is False
    assert report.interfaces == ()
    assert report.capture_warning == "live-захват недоступен: установите dumpcap"
