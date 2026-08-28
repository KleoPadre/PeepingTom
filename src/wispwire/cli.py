from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from wispwire.diagnostics import collect_doctor_report, list_interfaces
from wispwire.tshark import TsharkReadError, iter_packet_summaries
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
def open(
    capture_path: Path,
    limit: int = typer.Option(
        1000, min=1, help="Максимальное число выводимых пакетов."
    ),
) -> None:
    """Открыть готовый захват и вывести сводку пакетов."""
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

    packets_table = Table()
    packets_table.add_column("No.")
    packets_table.add_column("Time")
    packets_table.add_column("Source")
    packets_table.add_column("Destination")
    packets_table.add_column("Protocol")
    packets_table.add_column("Length")
    packets_table.add_column("Info")

    packet_found = False
    try:
        for packet in iter_packet_summaries(capture_path, status.path, limit):
            packet_found = True
            packets_table.add_row(
                _literal_text(packet.number),
                _literal_text(packet.relative_time),
                _literal_text(packet.source),
                _literal_text(packet.destination),
                _literal_text(packet.protocol),
                _literal_text(packet.length),
                _literal_text(packet.info),
            )
    except TsharkReadError as error:
        if packet_found:
            console.print(packets_table)
        console.print(f"Не удалось прочитать захват: {error}")
        raise typer.Exit(code=1) from None

    if packet_found:
        console.print(packets_table)
        return

    console.print("Пакеты не найдены.")


def _literal_text(value: object) -> Text:
    return Text(str(value))


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
