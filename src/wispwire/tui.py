"""TUI только для чтения сводок пакетов."""

from collections.abc import Callable
from typing import ClassVar

from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.binding import BindingType
from textual.containers import Container, VerticalScroll
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header, Input, Static

from wispwire.display_filters import format_display_filter_error
from wispwire.file_source import PacketQuery, PacketQueryResult
from wispwire.packet_widgets import rebuild_packet_table, render_packet_details
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
    #filters { height: auto; }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        ("q", "quit", "Выход"),
        ("tab", "focus_next", "Сменить фокус"),
        ("f", "focus_display_filter", "Фильтр"),
        ("/", "focus_info_search", "Info"),
        ("escape", "clear_active_filter", "Очистить"),
    ]

    def __init__(
        self,
        packets: tuple[PacketSummary, ...],
        source_name: str,
        read_details: Callable[[PacketSummary], PacketDetails],
        query_packets: Callable[[PacketQuery], PacketQueryResult] | None = None,
        initial_filter: str = "",
    ) -> None:
        super().__init__()
        self._all_packets = packets
        self._packets = packets
        self._source_name = source_name
        self._read_details = read_details
        self._query_packets = query_packets
        self._initial_filter = initial_filter
        self._filter_timer: Timer | None = None
        self._details_packet_number: int | None = None
        self.title = f"WispWire — {source_name}"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("Минимальный размер терминала — 80×24.", id="size-warning")
        with Container(id="filters"):
            yield Input(
                value=self._initial_filter,
                placeholder="Display filter",
                id="display-filter",
            )
            yield Input(placeholder="Info search", id="info-search")
            yield Static(id="filter-status")
        with Container(id="layout"):
            yield DataTable(id="packets")
            with VerticalScroll(id="details"):
                yield Static(id="details-content")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#packets", DataTable)
        table.cursor_type = "row"
        table.focus()
        self._update_layout(self.size.width, self.size.height)
        if self._packets:
            self._show_details(self._packets[0])
        if self._initial_filter and self._query_packets is not None:
            self._apply_filters()

    def on_resize(self, event: events.Resize) -> None:
        self._update_layout(event.size.width, event.size.height)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id not in ("display-filter", "info-search"):
            return
        if self._filter_timer is not None:
            self._filter_timer.stop()
        self._filter_timer = self.set_timer(0.2, self._apply_filters)

    def action_focus_display_filter(self) -> None:
        self.query_one("#display-filter", Input).focus()

    def action_focus_info_search(self) -> None:
        self.query_one("#info-search", Input).focus()

    def action_clear_active_filter(self) -> None:
        focused = self.focused
        if isinstance(focused, Input) and focused.id in (
            "display-filter",
            "info-search",
        ):
            focused.value = ""

    def _update_layout(self, width: int, height: int) -> None:
        self.query_one("#size-warning", Static).display = width < 80 or height < 24
        self._set_table_width(width >= 120)

    def _set_table_width(self, wide: bool) -> None:
        self.query_one("#layout").set_class(not wide, "narrow")
        self._rebuild_table(wide)

    def _rebuild_table(self, wide: bool) -> None:
        table = self.query_one("#packets", DataTable)
        rebuild_packet_table(table, self._packets, wide)
        if self._packets:
            return
        else:
            self._details_packet_number = None
            self.query_one("#details-content", Static).update(
                Text("Пакеты не найдены.")
            )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.cursor_row < len(self._packets):
            self._show_details(self._packets[event.cursor_row])

    def _apply_filters(self) -> None:
        self._filter_timer = None
        display_filter = self.query_one("#display-filter", Input).value
        info_query = self.query_one("#info-search", Input).value
        if self._query_packets is None:
            self._replace_packets(self._all_packets)
            return

        result = self._query_packets(
            PacketQuery(
                display_filter=display_filter,
                info_query=info_query,
                limit=len(self._all_packets) or 1,
            )
        )
        status = self.query_one("#filter-status", Static)
        if result.error is not None:
            status.update(Text(format_display_filter_error(result.error)))
            return

        status.update(Text(""))
        self._replace_packets(result.packets)

    def _replace_packets(self, packets: tuple[PacketSummary, ...]) -> None:
        self._packets = packets
        self._details_packet_number = None
        self._set_table_width(self.size.width >= 120)
        if self._packets:
            self._show_details(self._packets[0])

    def _show_details(self, packet: PacketSummary) -> None:
        if self._details_packet_number == packet.number:
            return
        self._details_packet_number = packet.number

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
            self.query_one("#details-content", Static).update(
                render_packet_details(packet, packet_details)
            )
            return
        self.query_one("#details-content", Static).update(Text("\n".join(details)))
