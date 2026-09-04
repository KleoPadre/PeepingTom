"""Сбор сведений для диагностики окружения WispWire."""

import platform
import re
import subprocess
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from wispwire.sqlite_support import SqliteFeatureStatus, check_fts5_trigram
from wispwire.wireshark import ToolStatus, inspect_tool

INTERFACE_PATTERN = re.compile(r"^\s*\d+\.\s+([^\s(]+)")


@dataclass(frozen=True)
class DoctorReport:
    """Сведения о Python и утилитах, нужных для работы WispWire."""

    python_version: str
    wispwire_version: str
    tools: tuple[ToolStatus, ...]
    interfaces: tuple[str, ...]
    capture_warning: str | None
    sqlite_fts5: SqliteFeatureStatus


def list_interfaces(
    dumpcap_path: str | Path = "dumpcap",
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[str, ...]:
    """Вернуть имена интерфейсов из вывода ``dumpcap -D`` без описаний."""
    try:
        result = run(
            [str(dumpcap_path), "-D"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ()

    if result.returncode != 0:
        return ()

    return tuple(
        match.group(1)
        for line in result.stdout.splitlines()
        if (match := INTERFACE_PATTERN.match(line)) is not None
    )


def collect_doctor_report(
    inspect: Callable[[str], ToolStatus] = inspect_tool,
    interfaces: Callable[[], tuple[str, ...]] = list_interfaces,
    sqlite_check: Callable[[], SqliteFeatureStatus] = check_fts5_trigram,
    platform_system: Callable[[], str] = platform.system,
) -> DoctorReport:
    """Собрать статус инструментов без запуска live-захвата."""
    tools = tuple(inspect(name) for name in ("tshark", "dumpcap", "mergecap"))
    tshark = next(tool for tool in tools if tool.name == "tshark")
    dumpcap = next(tool for tool in tools if tool.name == "dumpcap")
    dumpcap_available = dumpcap.path is not None and dumpcap.error is None
    available_interfaces = interfaces() if dumpcap_available else ()

    if tshark.path is None or tshark.error is not None:
        capture_warning = "live-захват недоступен: установите tshark"
    elif not dumpcap_available:
        capture_warning = "live-захват недоступен: установите dumpcap"
    elif not available_interfaces:
        if platform_system() == "Darwin":
            capture_warning = (
                "live-захват недоступен: dumpcap не вернул доступных интерфейсов. "
                "На macOS установите права захвата: "
                "brew install --cask wireshark-chmodbpf"
            )
        else:
            capture_warning = (
                "live-захват недоступен: dumpcap не вернул доступных интерфейсов"
            )
    else:
        capture_warning = None

    wispwire_version = _get_wispwire_version()
    sqlite_fts5 = sqlite_check()

    return DoctorReport(
        python_version=platform.python_version(),
        wispwire_version=wispwire_version,
        tools=tools,
        interfaces=available_interfaces,
        capture_warning=capture_warning,
        sqlite_fts5=sqlite_fts5,
    )


def _get_wispwire_version() -> str:
    """Определить версию установленного пакета или исходного дерева."""
    try:
        return version("wispwire")
    except PackageNotFoundError:
        pyproject_path = Path(__file__).parents[2] / "pyproject.toml"
        try:
            with pyproject_path.open("rb") as pyproject_file:
                project = tomllib.load(pyproject_file)["project"]
        except (OSError, KeyError, tomllib.TOMLDecodeError):
            return "неизвестна"

        project_version = project.get("version")
        return project_version if isinstance(project_version, str) else "неизвестна"
