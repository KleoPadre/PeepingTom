"""Интерфейс просмотра и управления live-захватом."""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
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
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    OptionList,
    Select,
    Static,
)
from textual.widgets.option_list import Option

from wispwire.capture import CaptureError, CaptureState
from wispwire.display_filters import (
    draft_filter_error,
    filter_suggestions,
    format_display_filter_error,
)
from wispwire.file_source import PacketQuery, PacketQueryResult
from wispwire.live_controller import (
    LiveCaptureController,
    LiveEvent,
    LiveFailure,
    LivePacketsAdded,
    LiveSaved,
    LiveStateChanged,
)
from wispwire.packet_widgets import rebuild_packet_table
from wispwire.packets import PacketDetails, PacketSummary
from wispwire.tshark import TsharkReadError

_STATE_LABELS = {
    CaptureState.RUNNING: "выполняется",
    CaptureState.STOPPED: "остановлен",
    CaptureState.LIMIT_REACHED: "достигнут лимит",
    CaptureState.FAILED: "ошибка",
    CaptureState.CLOSED: "закрыт",
}
_LIVE_PACKET_WINDOW = 2000


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


@dataclass(frozen=True)
class LiveCaptureRuntime:
    """Набор объектов для одного запущенного live-интерфейса."""

    controller: LiveCaptureController
    query_packets: Callable[[PacketQuery], PacketQueryResult]
    read_details: Callable[[int], PacketDetails]


class LiveCaptureApp(App[Path | None]):
    """Показывает подтверждённые пакеты и управляет live-захватом."""

    CSS = """
    Screen { background: #050505; color: #e8e8e8; }
    Header { display: none; }
    #capture-header { height: auto; padding: 0 1; background: #111111; }
    #filters { height: auto; padding: 1; background: #080808; }
    #filter-row { layout: horizontal; height: 3; }
    #filter-icon { width: 3; content-align: center middle; color: #00c781; }
    #interface-select { width: 16; margin: 0 1 0 0; }
    #display-filter { width: 1fr; margin: 0 1 0 0; border: round #303030; }
    #display-filter:focus { border: round #00c781; background: #0b2118; }
    #display-filter.filter-valid { border: round #00c781; }
    #display-filter.filter-invalid { border: round #ff5c5c; background: #2b0f12; }
    #display-filter.filter-invalid:focus { border: round #ff5c5c; background: #2b0f12; }
    #apply-filter { width: 10; margin: 0 1 0 0; }
    #clear-filter { width: 10; }
    Button { min-width: 10; }
    Button.-primary { background: #e8e8e8; color: #050505; text-style: bold; }
    Button.-warning { background: #181818; color: #d8d8d8; border: round #303030; }
    #filter-suggestions { display: none; height: 7; margin: 0 20 0 20; border: round #242424; background: #111111; }
    #filter-status { height: 1; color: #8a8a8a; padding: 0 0 0 3; }
    #layout { layout: vertical; }
    #layout.narrow { layout: vertical; }
    #packets { height: 2fr; }
    #packet-inspector { layout: horizontal; height: 1fr; border-top: solid #242424; }
    #details { width: 1fr; border-right: solid #242424; }
    #bytes { width: 1fr; }
    #layout.narrow #packets { width: 1fr; }
    #layout.narrow #packet-inspector { layout: vertical; }
    #layout.narrow #details { width: 1fr; height: 1fr; }
    #layout.narrow #bytes { width: 1fr; height: 1fr; }
    #size-warning { display: none; }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        ("s", "stop_and_analyze", "Остановить и открыть"),
        ("q", "quit", "Выход"),
        ("c", "continue_capture", "Продолжить"),
        ("r", "restart_capture", "Перезапустить"),
        ("w", "save_snapshot", "Снимок"),
        ("f", "focus_display_filter", "Фильтр"),
        ("enter", "apply_filter", "Применить фильтр"),
        ("escape", "clear_active_filter", "Очистить"),
        ("tab", "focus_next", "Сменить фокус"),
    ]

    def __init__(
        self,
        interface: str,
        controller: LiveCaptureController,
        query_packets: Callable[[PacketQuery], PacketQueryResult],
        read_details: Callable[[int], PacketDetails],
        display_filter_fields: tuple[str, ...] = (),
        available_interfaces: tuple[str, ...] = (),
        runtime_factory: Callable[[str], LiveCaptureRuntime] | None = None,
    ) -> None:
        super().__init__()
        self._interface = interface
        self._controller = controller
        self._query_packets = query_packets
        self._read_details = read_details
        self._display_filter_fields = display_filter_fields
        self._available_interfaces = available_interfaces or (interface,)
        self._runtime_factory = runtime_factory
        self._state: CaptureState | None = None
        self._all_packets: tuple[PacketSummary, ...] = ()
        self._packets: tuple[PacketSummary, ...] = ()
        self._pending_events: deque[LiveEvent] = deque()
        self._filter_timer: Timer | None = None
        self._details_packet_number: int | None = None
        self._details_requested_number: int | None = None
        self._query_generation = 0
        self._details_generation = 0
        self._generation = 0
        self._expected_restart_generation: int | None = None
        self._current_suggestions: tuple[str, ...] = ()
        self.title = f"WispWire — live-захват {interface}"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("Минимальный размер терминала — 80×24.", id="size-warning")
        with Container(id="capture-header"):
            yield Static(f"Интерфейс: {self._interface}", id="interface")
            yield Static(id="capture-status")
            yield Static(id="live-status")
        with Container(id="filters"):
            with Container(id="filter-row"):
                yield Static("▽", id="filter-icon")
                yield Select.from_values(
                    self._available_interfaces,
                    prompt="Интерфейс",
                    allow_blank=False,
                    value=self._interface,
                    id="interface-select",
                )
                yield Input(
                    placeholder='Display filter: dns, tcp.port == 443, ip.addr == "1.1.1.1"',
                    id="display-filter",
                )
                yield Button("Apply", id="apply-filter", variant="primary")
                yield Button("Cancel", id="clear-filter", variant="warning")
            yield OptionList(id="filter-suggestions")
            yield Static(
                "Enter или кнопка применяют Wireshark display filter.",
                id="filter-status",
            )
        with Container(id="layout"):
            yield DataTable(id="packets")
            with Container(id="packet-inspector"):
                with VerticalScroll(id="details"):
                    yield Static(id="details-content")
                with VerticalScroll(id="bytes"):
                    yield Static(id="bytes-content")
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
        if event.input.id == "display-filter":
            self._mark_filter_unknown()
            self._show_filter_hint(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "display-filter":
            self._apply_filters()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "interface-select" or event.value == Select.BLANK:
            return
        interface = str(event.value)
        if interface != self._interface:
            self._switch_interface(interface)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply-filter":
            self._apply_filters()
        elif event.button.id == "clear-filter":
            self._clear_filters()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id != "filter-suggestions":
            return
        selected_index = int(getattr(event, "index", -1))
        if selected_index < 0 or selected_index >= len(self._current_suggestions):
            return
        self._complete_filter_token(self._current_suggestions[selected_index])

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

    def action_clear_active_filter(self) -> None:
        focused = self.focused
        if isinstance(focused, Input) and focused.id == "display-filter":
            focused.value = ""
            self._apply_filters()

    def action_apply_filter(self) -> None:
        focused = self.focused
        if isinstance(focused, Input) and focused.id == "display-filter":
            self._apply_filters()

    def _clear_filters(self) -> None:
        self.query_one("#display-filter", Input).value = ""
        self._hide_filter_suggestions()
        self._mark_filter_unknown()
        self._apply_filters()

    def _drain_events(self) -> None:
        self._pending_events.extend(self._controller.drain_events())
        deferred: deque[LiveEvent] = deque()
        packet_batch_handled = False
        packets_changed = False

        while self._pending_events:
            event = self._pending_events.popleft()
            if isinstance(event, LivePacketsAdded):
                if (
                    self._expected_restart_generation is not None
                    or event.generation != self._generation
                ):
                    continue
                if packet_batch_handled:
                    deferred.append(event)
                    continue
                self._all_packets += event.packets
                packet_batch_handled = True
                packets_changed = True
            elif isinstance(event, LiveStateChanged):
                if self._expected_restart_generation is not None:
                    if event.generation != self._expected_restart_generation:
                        continue
                    self._expected_restart_generation = None
                elif event.generation < self._generation:
                    continue
                self._generation = event.generation
                self._state = event.state
                self._show_capture_status(event.packets, event.size)
            elif isinstance(event, LiveFailure):
                if event.generation < self._generation:
                    continue
                if (
                    self._expected_restart_generation is not None
                    and event.generation != self._expected_restart_generation
                ):
                    continue
                self._set_status(event.message)
            elif isinstance(event, LiveSaved):
                if event.open_in_file_tui:
                    self.exit(event.path)
                else:
                    self._set_status(f"Снимок сохранён: {event.path}")

        self._pending_events = deferred
        if packets_changed:
            if self._filters_are_active():
                self._schedule_filter_apply(1.0)
            else:
                self._replace_packets(self._all_packets)

    def _filters_are_active(self) -> bool:
        return bool(self.query_one("#display-filter", Input).value)

    def _apply_filters(self) -> None:
        self._filter_timer = None
        if not self._filters_are_active():
            self._query_generation += 1
            self._hide_filter_suggestions()
            self._mark_filter_unknown()
            self._replace_packets(self._all_packets)
            return
        query = PacketQuery(
            display_filter=self.query_one("#display-filter", Input).value,
            info_query="",
            limit=min(len(self._all_packets), _LIVE_PACKET_WINDOW) or 1,
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

    def _schedule_filter_apply(self, delay: float) -> None:
        if self._filter_timer is not None:
            self._filter_timer.stop()
        self._filter_timer = self.set_timer(delay, self._apply_filters)

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
            self.query_one("#filter-status", Static).update(
                Text(format_display_filter_error(event.result.error))
            )
            self._hide_filter_suggestions()
            self._mark_filter_invalid()
            return
        self._hide_filter_suggestions()
        self._mark_filter_valid()
        self._replace_packets(event.result.packets)

    def _replace_packets(self, packets: tuple[PacketSummary, ...]) -> None:
        selected_number = self._selected_packet_number()
        self._packets = _visible_packet_window(packets)
        self._rebuild_table(self.size.width >= 120)

        self._show_filter_result_status(len(packets), len(self._packets))

        if not self._packets:
            self._details_packet_number = None
            self.query_one("#details-content", Static).update(
                Text("Пакеты не найдены.")
            )
            self.query_one("#bytes-content", Static).update(Text(""))
            return

        selected_row = next(
            (
                index
                for index, packet in enumerate(self._packets)
                if packet.number == selected_number
            ),
            0,
        )
        table = self.query_one("#packets", DataTable)
        table.move_cursor(row=selected_row, column=0)
        self._show_details(self._packets[selected_row])

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
            bytes_text = Text("")
        else:
            assert event.details is not None
            text = Text(f"PACKET DETAILS\n\n{event.details.protocol_tree}")
            bytes_text = Text(f"PACKET BYTES\n\n{event.details.hex_ascii}")
        self.query_one("#details-content", Static).update(text)
        self.query_one("#bytes-content", Static).update(bytes_text)

    def _show_capture_status(self, packets: int, size: int) -> None:
        state = "ожидание данных" if self._state is None else _STATE_LABELS[self._state]
        self.query_one("#capture-status", Static).update(
            Text(f"Состояние: {state} · пакетов: {packets} · байт: {size}")
        )

    def _set_status(self, message: str) -> None:
        self.query_one("#live-status", Static).update(Text(message))

    def _switch_interface(self, interface: str) -> None:
        if self._runtime_factory is None:
            self._set_status("Переключение интерфейса недоступно.")
            return
        self._set_status(f"Переключение на {interface}…")
        try:
            self._controller.submit("quit")
            self._controller.join()
            runtime = self._runtime_factory(interface)
        except (CaptureError, OSError, TsharkReadError) as error:
            self._set_status(f"Не удалось переключить интерфейс: {error}")
            return

        self._interface = interface
        self._controller = runtime.controller
        self._query_packets = runtime.query_packets
        self._read_details = runtime.read_details
        self.title = f"WispWire — live-захват {interface}"
        self._clear_packets_for_interface_switch()
        self._show_capture_status(0, 0)
        self._set_status(f"Интерфейс переключён: {interface}")
        self._controller.start()

    def _clear_packets_for_interface_switch(self) -> None:
        self._state = None
        self._all_packets = ()
        self._packets = ()
        self._pending_events.clear()
        self._filter_timer = None
        self._details_packet_number = None
        self._details_requested_number = None
        self._query_generation += 1
        self._details_generation += 1
        self._generation = 0
        self._expected_restart_generation = None
        self.query_one("#display-filter", Input).value = ""
        self._hide_filter_suggestions()
        self._mark_filter_unknown()
        self.query_one("#details-content", Static).update(Text("Пакеты не найдены."))
        self.query_one("#bytes-content", Static).update(Text(""))
        self._rebuild_table(self.size.width >= 120)

    def _show_filter_hint(self, value: str) -> None:
        draft_error = draft_filter_error(value, self._display_filter_fields)
        if draft_error is not None:
            self._hide_filter_suggestions()
            self._mark_filter_invalid()
            self.query_one("#filter-status", Static).update(Text(draft_error))
            return

        suggestions = filter_suggestions(value, self._display_filter_fields)
        self._update_filter_suggestions(suggestions)
        if suggestions:
            self.query_one("#filter-status", Static).update(
                Text(f"Подсказка: {', '.join(suggestions)}")
            )
        elif value.strip():
            self.query_one("#filter-status", Static).update(
                Text("Enter или Применить запустит Wireshark display filter.")
            )
        else:
            self._show_filter_result_status(len(self._all_packets), len(self._packets))

    def _update_filter_suggestions(self, suggestions: tuple[str, ...]) -> None:
        self._current_suggestions = suggestions
        option_list = self.query_one("#filter-suggestions", OptionList)
        option_list.clear_options()
        option_list.add_options(
            Option(_suggestion_label(suggestion)) for suggestion in suggestions
        )
        option_list.display = bool(suggestions)

    def _hide_filter_suggestions(self) -> None:
        self._current_suggestions = ()
        option_list = self.query_one("#filter-suggestions", OptionList)
        option_list.clear_options()
        option_list.display = False

    def _complete_filter_token(self, suggestion: str) -> None:
        display_filter = self.query_one("#display-filter", Input)
        display_filter.value = _replace_current_filter_token(
            display_filter.value, suggestion
        )
        self._hide_filter_suggestions()
        display_filter.focus()

    def _mark_filter_valid(self) -> None:
        display_filter = self.query_one("#display-filter", Input)
        display_filter.set_class(True, "filter-valid")
        display_filter.set_class(False, "filter-invalid")

    def _mark_filter_invalid(self) -> None:
        display_filter = self.query_one("#display-filter", Input)
        display_filter.set_class(False, "filter-valid")
        display_filter.set_class(True, "filter-invalid")

    def _mark_filter_unknown(self) -> None:
        display_filter = self.query_one("#display-filter", Input)
        display_filter.set_class(False, "filter-valid")
        display_filter.set_class(False, "filter-invalid")

    def _show_filter_result_status(self, total: int, visible: int) -> None:
        status = self.query_one("#filter-status", Static)
        if total > visible:
            status.update(Text(f"показаны последние {visible} из {total} пакетов"))
        elif self._filters_are_active():
            status.update(Text(f"Валидный фильтр · показано {visible} пакетов"))
        else:
            status.update(Text("Enter или кнопка применяют Wireshark display filter."))

    def _state_is_known(self) -> bool:
        if self._state is not None:
            return True
        self._set_status("Состояние захвата ещё не получено.")
        return False

    def _clear_packets_for_restart(self) -> None:
        self._expected_restart_generation = self._generation + 1
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


def _visible_packet_window(
    packets: tuple[PacketSummary, ...],
) -> tuple[PacketSummary, ...]:
    return packets[-_LIVE_PACKET_WINDOW:]


def _suggestion_label(suggestion: str) -> str:
    if "." in suggestion:
        return f"{suggestion} ="
    return suggestion


def _replace_current_filter_token(value: str, suggestion: str) -> str:
    return re.sub(r"([A-Za-z_][A-Za-z0-9_.]*)$", suggestion, value)
