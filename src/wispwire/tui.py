"""TUI только для чтения сводок пакетов."""

from collections.abc import Callable
from typing import ClassVar

from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.binding import BindingType
from textual.containers import Container
from textual.widgets import DataTable, Footer, Header, Static

from wispwire.packets import PacketDetails, PacketSummary
from wispwire.tshark import TsharkReadError


class WispWireApp(App[None]):
    """Показывает список пакетов и сведения о выбранном пакете."""

    CSS = """
    #layout { layout: horizontal; }
    #layout.narrow { layout: vertical; }
    #packets { width: 2fr; }
    #details { width: 1fr; }
    #layout.narrow #packets { width: 1fr; }
    #layout.narrow #details { width: 1fr; }
    #size-warning { display: none; }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        ("q", "quit", "Выход"),
        ("tab", "focus_next", "Сменить фокус"),
    ]

    def __init__(
        self,
        packets: tuple[PacketSummary, ...],
        source_name: str,
        read_details: Callable[[PacketSummary], PacketDetails],
    ) -> None:
        super().__init__()
        self._packets = packets
        self._source_name = source_name
        self._read_details = read_details
        self.title = f"WispWire — {source_name}"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("Минимальный размер терминала — 80×24.", id="size-warning")
        with Container(id="layout"):
            yield DataTable(id="packets")
            yield Static(id="details")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#packets", DataTable)
        table.cursor_type = "row"
        table.focus()
        self._update_layout(self.size.width, self.size.height)
        if self._packets:
            self._show_details(self._packets[0])

    def on_resize(self, event: events.Resize) -> None:
        self._update_layout(event.size.width, event.size.height)

    def _update_layout(self, width: int, height: int) -> None:
        self.query_one("#size-warning", Static).display = width < 80 or height < 24
        self._set_table_width(width >= 120)

    def _set_table_width(self, wide: bool) -> None:
        self.query_one("#layout").set_class(not wide, "narrow")
        self._rebuild_table(wide)

    def _rebuild_table(self, wide: bool) -> None:
        table = self.query_one("#packets", DataTable)
        selected_row = table.cursor_row
        table.clear(columns=True)
        if wide:
            table.add_columns(
                "No.",
                "Time",
                "Source",
                "Destination",
                "Protocol",
                "Length",
                "Info",
            )
        else:
            table.add_columns("No.", "Source", "Protocol", "Info")
        for packet in self._packets:
            table.add_row(*self._row_values(packet, wide))
        if self._packets:
            table.move_cursor(row=min(selected_row, len(self._packets) - 1), column=0)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.cursor_row < len(self._packets):
            self._show_details(self._packets[event.cursor_row])

    def _row_values(self, packet: PacketSummary, wide: bool) -> tuple[Text, ...]:
        values = (
            Text(str(packet.number)),
            Text(packet.relative_time),
            Text(packet.source),
            Text(packet.destination),
            Text(packet.protocol),
            Text(str(packet.length)),
            Text(packet.info),
        )
        if wide:
            return values
        return values[0], values[2], values[4], values[6]

    def _show_details(self, packet: PacketSummary) -> None:
        summary = (
            f"No.: {packet.number}",
            f"Time: {packet.relative_time}",
            f"Source: {packet.source}",
            f"Destination: {packet.destination}",
            f"Protocol: {packet.protocol}",
            f"Length: {packet.length}",
            f"Info: {packet.info}",
        )
        details: tuple[str, ...]
        try:
            packet_details = self._read_details(packet)
        except (TsharkReadError, OSError) as error:
            details = (*summary, "", f"Не удалось загрузить детали: {error}")
        else:
            details = (
                *summary,
                "",
                "Дерево протоколов:",
                packet_details.protocol_tree,
                "",
                "Hex/ASCII:",
                packet_details.hex_ascii,
            )
        self.query_one("#details", Static).update(Text("\n".join(details)))
