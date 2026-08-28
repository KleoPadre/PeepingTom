from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired

from wispwire.wireshark import inspect_tool


def fake_version_run(*_: object, **__: object) -> CompletedProcess[str]:
    return CompletedProcess(
        ["tshark", "--version"],
        0,
        "TShark (Wireshark) 4.4.0\n",
        "",
    )


def test_inspect_tool_returns_version_for_found_program() -> None:
    status = inspect_tool(
        "tshark", which=lambda _: "/opt/bin/tshark", run=fake_version_run
    )

    assert status.path == Path("/opt/bin/tshark")
    assert status.version == "4.4.0"
    assert status.error is None


def test_inspect_tool_reports_missing_program() -> None:
    status = inspect_tool("dumpcap", which=lambda _: None)

    assert status.path is None
    assert status.error == "утилита не найдена в PATH"


def test_inspect_tool_reports_unsuccessful_version_command() -> None:
    status = inspect_tool(
        "tshark",
        which=lambda _: "/opt/bin/tshark",
        run=lambda *_args, **_kwargs: CompletedProcess(
            ["tshark", "--version"], 1, "", "ошибка"
        ),
    )

    assert status.path == Path("/opt/bin/tshark")
    assert status.version is None
    assert status.error is not None


def test_inspect_tool_reports_version_command_timeout() -> None:
    def run_with_timeout(*_: object, **__: object) -> CompletedProcess[str]:
        raise TimeoutExpired(["tshark", "--version"], 5)

    status = inspect_tool(
        "tshark", which=lambda _: "/opt/bin/tshark", run=run_with_timeout
    )

    assert status.path == Path("/opt/bin/tshark")
    assert status.version is None
    assert status.error is not None


def test_inspect_tool_reports_unrecognized_version() -> None:
    status = inspect_tool(
        "tshark",
        which=lambda _: "/opt/bin/tshark",
        run=lambda *_args, **_kwargs: CompletedProcess(
            ["tshark", "--version"], 0, "версия неизвестна\n", ""
        ),
    )

    assert status.path == Path("/opt/bin/tshark")
    assert status.version is None
    assert status.error is not None
