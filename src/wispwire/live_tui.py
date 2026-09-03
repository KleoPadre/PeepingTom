"""Интерфейс просмотра и управления live-захватом."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import ClassVar

from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.binding import BindingType
from textual.containers import Container, VerticalScroll
from textual.message import Message
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header, Input, Static

from wispwire.capture import CaptureState
from wispwire.file_source import PacketQuery, PacketQueryResult
from wispwire.live_controller import (
    LiveCaptureController,
    LiveEvent,
    LiveFailure,
    LivePacketsAdded,
    LiveSaved,
    LiveStateChanged,
)
from wispwire.packet_widgets import rebuild_packet_table, render_packet_details
from wispwire.packets import PacketDetails, PacketSummary
from wispwire.tshark import TsharkReadError

_STATE_LABELS = {
    CaptureState.RUNNING: "выполняется",
    CaptureState.STOPPED: "остановлен",
    CaptureState.LIMIT_REACHED: "достигнут лимит",
    CaptureState.FAILED: "ошибка",
    CaptureState.CLOSED: "закрыт",
}


class LiveQueryCompleted(Message):
    """Результат фонового запроса пакетов."""

    def __init__(self, generation: int, result: PacketQueryResult) -> None:
        super().__init__()
        self.generation = generation
        self.result = result


class LiveDetailsCompleted(Message):
    """Результат фонового чтения подробностей пакета."""

    def __init__(
        self,
        generation: int,
        number: int,
        details: PacketDetails | None,
        error: str | None,
    ) -> None:
        super().__init__()
        self.generation = generation
        self.number = number
        self.details = details
        self.error = error


class LiveCaptureApp(App[Path | None]):
    """Показывает подтверждённые пакеты и управляет live-захватом."""

    CSS = """
    #layout { layout: horizontal; }
    #layout.narrow { layout: vertical; }
    #packets { width: 2fr; }
    #details { width: 1fr; }
    #layout.narrow #packets { width: 1fr; }
    #layout.narrow #details { width: 1fr; }
    #size-warning { display: none; }
    #capture-header { height: auto; }
    #filters { height: auto; }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        ("s", "stop_and_analyze", "Остановить и открыть"),
        ("q", "quit", "Выход"),
        ("c", "continue_capture", "Продолжить"),
        ("r", "restart_capture", "Перезапустить"),
        ("w", "save_snapshot", "Снимок"),
        ("f", "focus_display_filter", "Фильтр"),
        ("/", "focus_info_search", "Info"),
        ("escape", "clear_active_filter", "Очистить"),
        ("tab", "focus_next", "Сменить фокус"),
    ]

    def __init__(
        self,
        interface: str,
        controller: LiveCaptureController,
        query_packets: Callable[[PacketQuery], PacketQueryResult],
        read_details: Callable[[int], PacketDetails],
    ) -> None:
        super().__init__()
        self._interface = interface
        self._controller = controller
        self._query_packets = query_packets
        self._read_details = read_details
        self._state: CaptureState | None = None
        self._all_packets: tuple[PacketSummary, ...] = ()
        self._packets: tuple[PacketSummary, ...] = ()
        self._pending_events: deque[LiveEvent] = deque()
        self._filter_timer: Timer | None = None
        self._details_packet_number: int | None = None
        self._details_requested_number: int | None = None
        self._query_generation = 0
        self._details_generation = 0
        self.title = f"WispWire — live-захват {interface}"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("Минимальный размер терминала — 80×24.", id="size-warning")
        with Container(id="capture-header"):
            yield Static(f"Интерфейс: {self._interface}", id="interface")
            yield Static(id="capture-status")
            yield Static(id="live-status")
        with Container(id="filters"):
            yield Input(placeholder="Display filter", id="display-filter")
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
        self._show_capture_status(0, 0)
        self._controller.start()
        self.set_interval(0.1, self._drain_events)

    def on_unmount(self) -> None:
        self._controller.submit("quit")
        self._controller.join()

    def on_resize(self, event: events.Resize) -> None:
        self._update_layout(event.size.width, event.size.height)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id not in ("display-filter", "info-search"):
            return
        if self._filter_timer is not None:
            self._filter_timer.stop()
        self._filter_timer = self.set_timer(0.2, self._apply_filters)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.cursor_row < len(self._packets):
            self._show_details(self._packets[event.cursor_row])

    def action_stop_and_analyze(self) -> None:
        if not self._state_is_known():
            return
        if self._state is CaptureState.RUNNING:
            self._controller.submit("stop_and_save")
        else:
            self._set_status("Остановить можно только запущенный захват.")

    def action_continue_capture(self) -> None:
        if not self._state_is_known():
            return
        if self._state is CaptureState.STOPPED:
            self._controller.submit("continue")
        else:
            self._set_status("Продолжить можно только остановленный захват.")

    def action_restart_capture(self) -> None:
        if not self._state_is_known():
            return
        if self._state in (
            CaptureState.STOPPED,
            CaptureState.FAILED,
            CaptureState.LIMIT_REACHED,
        ):
            self._clear_packets_for_restart()
            self._controller.submit("restart")
        else:
            self._set_status(
                "Перезапуск доступен только после остановки, ошибки или лимита."
            )

    def action_save_snapshot(self) -> None:
        if not self._state_is_known():
            return
        if self._state in (
            CaptureState.RUNNING,
            CaptureState.STOPPED,
            CaptureState.LIMIT_REACHED,
        ):
            self._controller.submit("save")
        else:
            self._set_status("Сохранение недоступно в текущем состоянии захвата.")

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

    def _drain_events(self) -> None:
        self._pending_events.extend(self._controller.drain_events())
        deferred: deque[LiveEvent] = deque()
        packet_batch_handled = False
        packets_changed = False

        while self._pending_events:
            event = self._pending_events.popleft()
            if isinstance(event, LivePacketsAdded):
                if packet_batch_handled:
                    deferred.append(event)
                    continue
                self._all_packets += event.packets
                packet_batch_handled = True
                packets_changed = True
            elif isinstance(event, LiveStateChanged):
                self._state = event.state
                self._show_capture_status(event.packets, event.size)
            elif isinstance(event, LiveFailure):
                self._set_status(event.message)
            elif isinstance(event, LiveSaved):
                if event.open_in_file_tui:
                    self.exit(event.path)
                else:
                    self._set_status(f"Снимок сохранён: {event.path}")

        self._pending_events = deferred
        if packets_changed:
            if self._filters_are_active():
                self._apply_filters()
            else:
                self._replace_packets(self._all_packets)

    def _filters_are_active(self) -> bool:
        return bool(
            self.query_one("#display-filter", Input).value
            or self.query_one("#info-search", Input).value
        )

    def _apply_filters(self) -> None:
        self._filter_timer = None
        query = PacketQuery(
            display_filter=self.query_one("#display-filter", Input).value,
            info_query=self.query_one("#info-search", Input).value,
            limit=len(self._all_packets) or 1,
        )
        self._query_generation += 1
        generation = self._query_generation
        self.run_worker(
            partial(self._run_query, generation, query),
            name="live-query",
            group="live-query",
            exit_on_error=False,
            exclusive=True,
            thread=True,
        )

    def _run_query(self, generation: int, query: PacketQuery) -> None:
        try:
            result = self._query_packets(query)
        except (TsharkReadError, OSError) as error:
            result = PacketQueryResult((), str(error))
        self.post_message(LiveQueryCompleted(generation, result))

    def on_live_query_completed(self, event: LiveQueryCompleted) -> None:
        if event.generation != self._query_generation:
            return
        if event.result.error is not None:
            self.query_one("#filter-status", Static).update(Text(event.result.error))
            return
        self.query_one("#filter-status", Static).update(Text(""))
        self._replace_packets(event.result.packets)

    def _replace_packets(self, packets: tuple[PacketSummary, ...]) -> None:
        selected_number = self._selected_packet_number()
        self._packets = packets
        self._rebuild_table(self.size.width >= 120)

        if not packets:
            self._details_packet_number = None
            self.query_one("#details-content", Static).update(
                Text("Пакеты не найдены.")
            )
            return

        selected_row = next(
            (
                index
                for index, packet in enumerate(packets)
                if packet.number == selected_number
            ),
            0,
        )
        table = self.query_one("#packets", DataTable)
        table.move_cursor(row=selected_row, column=0)
        self._show_details(packets[selected_row])

    def _selected_packet_number(self) -> int | None:
        table = self.query_one("#packets", DataTable)
        if table.cursor_row < len(self._packets):
            return self._packets[table.cursor_row].number
        return None

    def _update_layout(self, width: int, height: int) -> None:
        self.query_one("#size-warning", Static).display = width < 80 or height < 24
        self.query_one("#layout").set_class(width < 120, "narrow")
        self._rebuild_table(width >= 120)

    def _rebuild_table(self, wide: bool) -> None:
        rebuild_packet_table(self.query_one("#packets", DataTable), self._packets, wide)
        if not self._packets:
            self.query_one("#details-content", Static).update(
                Text("Пакеты не найдены.")
            )

    def _show_details(self, packet: PacketSummary) -> None:
        if packet.number in (
            self._details_packet_number,
            self._details_requested_number,
        ):
            return
        self._details_requested_number = packet.number
        self._details_generation += 1
        generation = self._details_generation
        self.run_worker(
            partial(self._run_details, generation, packet.number),
            name="live-details",
            group="live-details",
            exit_on_error=False,
            exclusive=True,
            thread=True,
        )

    def _run_details(self, generation: int, number: int) -> None:
        try:
            details = self._read_details(number)
        except (TsharkReadError, OSError) as error:
            self.post_message(
                LiveDetailsCompleted(generation, number, None, str(error))
            )
        else:
            self.post_message(LiveDetailsCompleted(generation, number, details, None))

    def on_live_details_completed(self, event: LiveDetailsCompleted) -> None:
        if event.generation != self._details_generation:
            return
        self._details_requested_number = None
        packet = next(
            (packet for packet in self._packets if packet.number == event.number), None
        )
        if packet is None or self._selected_packet_number() != event.number:
            return
        self._details_packet_number = event.number
        if event.error is not None:
            text = Text(f"Не удалось загрузить детали: {event.error}")
        else:
            assert event.details is not None
            text = render_packet_details(packet, event.details)
        self.query_one("#details-content", Static).update(text)

    def _show_capture_status(self, packets: int, size: int) -> None:
        state = "ожидание данных" if self._state is None else _STATE_LABELS[self._state]
        self.query_one("#capture-status", Static).update(
            Text(f"Состояние: {state} · пакетов: {packets} · байт: {size}")
        )

    def _set_status(self, message: str) -> None:
        self.query_one("#live-status", Static).update(Text(message))

    def _state_is_known(self) -> bool:
        if self._state is not None:
            return True
        self._set_status("Состояние захвата ещё не получено.")
        return False

    def _clear_packets_for_restart(self) -> None:
        self._all_packets = ()
        self._packets = ()
        self._pending_events = deque(
            event
            for event in self._pending_events
            if not isinstance(event, LivePacketsAdded)
        )
        self._query_generation += 1
        self._details_generation += 1
        self._details_packet_number = None
        self._details_requested_number = None
        self._rebuild_table(self.size.width >= 120)
