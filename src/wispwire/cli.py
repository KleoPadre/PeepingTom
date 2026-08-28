import typer
from rich.console import Console
from rich.table import Table

from wispwire.diagnostics import collect_doctor_report, list_interfaces

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
