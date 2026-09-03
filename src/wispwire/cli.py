from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from wispwire.capture import CaptureError, CaptureSession
from wispwire.diagnostics import collect_doctor_report, list_interfaces
from wispwire.file_source import FilePacketSource
from wispwire.live_controller import LiveCaptureController
from wispwire.live_source import LivePacketSource
from wispwire.live_tui import LiveCaptureApp
from wispwire.packets import PacketDetails, PacketSummary
from wispwire.sessions import SessionStorage
from wispwire.tshark import TsharkReadError, read_packet_details
from wispwire.tui import WispWireApp
from wispwire.wireshark import inspect_tool

app = typer.Typer(
    help="WispWire — терминальная утилита для диагностики сетевого анализа."
)
console = Console()


@app.callback()
def main() -> None:
    """Запустить WispWire."""


@app.command()
def doctor() -> None:
    """Проверить утилиты и доступность live-захвата."""
    report = collect_doctor_report()
    console.print("[bold]Диагностика WispWire[/bold]")
    console.print(f"Python: {report.python_version}")
    console.print(f"Версия WispWire: {report.wispwire_version}")
    sqlite_status = "OK" if report.sqlite_fts5.available else "ОШИБКА"
    console.print(f"SQLite FTS5 trigram: {sqlite_status}")

    tools_table = Table(title="Утилиты")
    tools_table.add_column("Утилита")
    tools_table.add_column("Путь")
    tools_table.add_column("Версия")
    tools_table.add_column("Статус")
    for tool in report.tools:
        status = "OK" if tool.error is None else "ОШИБКА"
        tools_table.add_row(
            tool.name,
            str(tool.path) if tool.path is not None else "—",
            tool.version or "—",
            status,
        )
    console.print(tools_table)

    _print_interfaces(report.interfaces)
    if not report.sqlite_fts5.available:
        console.print(f"[yellow]Предупреждение: {report.sqlite_fts5.error}[/yellow]")
    if report.capture_warning is not None:
        console.print(f"[yellow]Предупреждение: {report.capture_warning}[/yellow]")


@app.command()
def interfaces() -> None:
    """Показать доступные интерфейсы для live-захвата."""
    available_interfaces = list_interfaces()
    if not available_interfaces:
        console.print("Интерфейсы не найдены. Проверьте dumpcap и права доступа.")
        return

    _print_interfaces(available_interfaces)


@app.command()
def capture(
    interface: str = typer.Option(..., "--iface", help="Интерфейс для live-захвата."),
) -> None:
    """Запустить live-захват в live-TUI."""
    dumpcap = inspect_tool("dumpcap")
    if dumpcap.path is None or dumpcap.error is not None:
        console.print("dumpcap недоступен. Запустите `wispwire doctor` для проверки.")
        raise typer.Exit(code=1)

    mergecap = inspect_tool("mergecap")
    if mergecap.path is None or mergecap.error is not None:
        console.print("mergecap недоступен. Запустите `wispwire doctor` для проверки.")
        raise typer.Exit(code=1)

    if interface not in list_interfaces():
        console.print(f"Интерфейс {interface} недоступен.")
        raise typer.Exit(code=2)

    tshark = inspect_tool("tshark")
    if tshark.path is None or tshark.error is not None:
        console.print("TShark недоступен. Запустите `wispwire doctor` для проверки.")
        raise typer.Exit(code=1)

    session = CaptureSession(
        dumpcap.path,
        mergecap.path,
        interface,
        storage=SessionStorage(),
    )
    try:
        source = LivePacketSource(tshark.path)
        controller = LiveCaptureController(
            session,
            source,
            destination_factory=_capture_destination,
        )
        saved_path = LiveCaptureApp(
            interface,
            controller,
            source.query,
            source.read_details,
        ).run()
        if saved_path is not None:
            _open_capture_in_tui(saved_path)
    except CaptureError as error:
        console.print(f"Ошибка live-захвата: {error}")
        raise typer.Exit(code=1) from None


@app.command()
def open(
    capture_path: Path,
    limit: int = typer.Option(
        1000, min=1, help="Максимальное число выводимых пакетов."
    ),
    display_filter: str = typer.Option("", "--filter", help="Display filter TShark."),
) -> None:
    """Открыть готовый захват в TUI."""
    _open_capture_in_tui(capture_path, limit=limit, display_filter=display_filter)


def _open_capture_in_tui(
    capture_path: Path,
    *,
    limit: int = 1000,
    display_filter: str = "",
) -> None:
    """Открыть существующий файл захвата через общий файловый TUI."""
    if not capture_path.exists():
        console.print("Файл захвата не найден.")
        raise typer.Exit(code=2)
    if not capture_path.is_file():
        console.print("Ожидается файл захвата.")
        raise typer.Exit(code=2)

    status = inspect_tool("tshark")
    if status.path is None:
        console.print("TShark недоступен. Запустите `wispwire doctor` для проверки.")
        raise typer.Exit(code=1)
    tshark_path = status.path

    source: FilePacketSource | None = None
    try:
        source = FilePacketSource(capture_path, tshark_path)
        packets = source.load(limit)
        if not packets:
            console.print("Пакеты не найдены.")
            return

        def read_details(packet: PacketSummary) -> PacketDetails:
            return read_packet_details(capture_path, tshark_path, packet.number)

        WispWireApp(
            packets,
            capture_path.name,
            read_details,
            query_packets=source.query,
            initial_filter=display_filter,
        ).run()
    except TsharkReadError as error:
        console.print(f"Не удалось прочитать захват: {error}")
        raise typer.Exit(code=1) from None
    finally:
        if source is not None:
            source.close()


def _capture_destination() -> Path:
    """Вернуть новый постоянный путь для live-захвата, не создавая файл."""
    catalog = Path.home() / "WispWire" / "Captures"
    catalog.mkdir(parents=True, exist_ok=True)
    stem = f"capture_{datetime.now().astimezone():%Y-%m-%d_%H-%M-%S}"
    destination = catalog / f"{stem}.pcapng"
    suffix = 2
    while destination.exists():
        destination = catalog / f"{stem}-{suffix}.pcapng"
        suffix += 1
    return destination


def _print_interfaces(interfaces: tuple[str, ...]) -> None:
    """Вывести нумерованный список сетевых интерфейсов."""
    if not interfaces:
        console.print("Интерфейсы не найдены.")
        return

    console.print("[bold]Интерфейсы[/bold]")
    for number, interface in enumerate(interfaces, start=1):
        console.print(f"{number}. {interface}")


if __name__ == "__main__":
    app()
