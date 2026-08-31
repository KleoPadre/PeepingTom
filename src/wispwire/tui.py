"""Read-only TUI для просмотра сводок пакетов."""

from typing import ClassVar

from rich.markup import escape
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import BindingType
from textual.containers import Container
from textual.widgets import DataTable, Footer, Header, Static

from wispwire.packets import PacketSummary


class WispWireApp(App[None]):
    """Показывает список пакетов и сведения о выбранном пакете."""

    CSS = """
    #layout { layout: horizontal; }
    #layout.narrow { layout: vertical; }
    #packets { width: 2fr; }
    #details { width: 1fr; }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        ("q", "quit", "Выход"),
        ("tab", "focus_next", "Сменить фокус"),
    ]

    def __init__(self, packets: tuple[PacketSummary, ...], source_name: str) -> None:
        super().__init__()
        self._packets = packets
        self._source_name = source_name
        self.title = f"WispWire — {source_name}"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Container(id="layout"):
            yield DataTable(id="packets")
            yield Static(id="details")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#packets", DataTable)
        table.cursor_type = "row"
        table.add_columns(
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"
        )
        for packet in self._packets:
            table.add_row(*self._row_values(packet))
        table.focus()
        if self._packets:
            self._show_details(self._packets[0])

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.cursor_row < len(self._packets):
            self._show_details(self._packets[event.cursor_row])

    def _row_values(self, packet: PacketSummary) -> tuple[str, ...]:
        return (
            escape(str(packet.number)),
            escape(packet.relative_time),
            escape(packet.source),
            escape(packet.destination),
            escape(packet.protocol),
            escape(str(packet.length)),
            escape(packet.info),
        )

    def _show_details(self, packet: PacketSummary) -> None:
        details = "\n".join(
            (
                f"No.: {packet.number}",
                f"Time: {packet.relative_time}",
                f"Source: {packet.source}",
                f"Destination: {packet.destination}",
                f"Protocol: {packet.protocol}",
                f"Length: {packet.length}",
                f"Info: {packet.info}",
            )
        )
        self.query_one("#details", Static).update(Text(details))
