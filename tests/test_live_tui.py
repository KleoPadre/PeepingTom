import threading
from pathlib import Path
from typing import Literal

import pytest
from textual.containers import VerticalScroll
from textual.widgets import Button, DataTable, Input, OptionList, Select, Static

from wispwire.capture import CaptureState
from wispwire.file_source import PacketQuery, PacketQueryResult
from wispwire.live_controller import (
    LiveEvent,
    LiveFailure,
    LivePacketsAdded,
    LiveSaved,
    LiveStateChanged,
)
from wispwire.live_tui import LiveCaptureApp, LiveCaptureRuntime
from wispwire.packets import PacketDetails, PacketSummary

LiveCommand = Literal["stop_and_save", "continue", "restart", "save", "quit"]


def packet(number: int, info: str = "Запрос") -> PacketSummary:
    return PacketSummary(
        number=number,
        relative_time=f"{number - 1}.000000",
        source="10.0.0.1",
        destination="10.0.0.2",
        protocol="DNS",
        length=72,
        info=info,
    )


def tcp_packet(number: int, info: str = "ACK") -> PacketSummary:
    return PacketSummary(
        number=number,
        relative_time=f"{number - 1}.000000",
        source="10.0.0.1",
        destination="10.0.0.2",
        protocol="TCP",
        length=86,
        info=info,
    )


class FakeController:
    def __init__(self, events: tuple[LiveEvent, ...] = ()) -> None:
        self._events = list(events)
        self.commands: list[LiveCommand] = []
        self.drain_calls = 0
        self.started = False
        self.joined = False

    def start(self) -> None:
        self.started = True

    def submit(self, command: LiveCommand) -> None:
        self.commands.append(command)

    def drain_events(self) -> tuple[LiveEvent, ...]:
        self.drain_calls += 1
        events = tuple(self._events)
        self._events.clear()
        return events

    def join(self) -> None:
        self.joined = True

    def publish(self, *events: LiveEvent) -> None:
        self._events.extend(events)


def query_packets(_query: PacketQuery) -> PacketQueryResult:
    return PacketQueryResult((), None)


def read_details(number: int) -> PacketDetails:
    return PacketDetails(f"Frame {number}", f"{number:04x}  aa")


def status_text(app: LiveCaptureApp, selector: str = "#live-status") -> str:
    return str(app.query_one(selector, Static).renderable)


@pytest.mark.asyncio
async def test_live_app_adds_one_controller_batch_per_update() -> None:
    controller = FakeController(
        events=(
            LivePacketsAdded((packet(1), packet(2))),
            LivePacketsAdded((packet(3),)),
        )
    )
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        table = app.query_one("#packets", DataTable)

        assert table.row_count == 2
        assert next(str(value) for value in table.get_row_at(1)) == "2"
        assert controller.drain_calls == 1

        await pilot.pause(0.11)
        assert table.row_count == 3


@pytest.mark.asyncio
async def test_live_app_shows_recent_packet_window_instead_of_all_rows() -> None:
    packets = tuple(packet(number) for number in range(1, 2102))
    controller = FakeController(events=(LivePacketsAdded(packets),))
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        table = app.query_one("#packets", DataTable)

        assert table.row_count == 2000
        assert next(str(value) for value in table.get_row_at(0)) == "102"
        assert "показаны последние 2000 из 2101" in status_text(app, "#filter-status")


@pytest.mark.asyncio
async def test_live_app_preserves_selected_row_when_batch_arrives() -> None:
    controller = FakeController(events=(LivePacketsAdded((packet(1), packet(2))),))
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        table = app.query_one("#packets", DataTable)
        table.move_cursor(row=1)
        controller.publish(LivePacketsAdded((packet(3),)))
        await pilot.pause(0.11)

        assert table.cursor_row == 1
        assert next(str(value) for value in table.get_row_at(1)) == "2"


@pytest.mark.asyncio
async def test_live_callbacks_never_run_in_main_thread() -> None:
    callback_threads: list[threading.Thread] = []

    def threaded_query(_query: PacketQuery) -> PacketQueryResult:
        callback_threads.append(threading.current_thread())
        return PacketQueryResult((packet(1),), None)

    def threaded_details(number: int) -> PacketDetails:
        callback_threads.append(threading.current_thread())
        return PacketDetails(f"Frame {number}", "0000  aa")

    controller = FakeController(events=(LivePacketsAdded((packet(1),)),))
    app = LiveCaptureApp("en0", controller, threaded_query, threaded_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f", "d", "n", "s")
        await pilot.press("enter")
        await pilot.pause(0.25)

        assert len(callback_threads) == 2
        assert all(thread is not threading.main_thread() for thread in callback_threads)


@pytest.mark.asyncio
async def test_live_display_filter_runs_only_when_submitted() -> None:
    calls: list[PacketQuery] = []

    def recording_query(query: PacketQuery) -> PacketQueryResult:
        calls.append(query)
        return PacketQueryResult((tcp_packet(1),), None)

    controller = FakeController(events=(LivePacketsAdded((tcp_packet(1),)),))
    app = LiveCaptureApp("en0", controller, recording_query, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f", "t", "c", "p")
        await pilot.pause(0.25)

        assert calls == []

        await pilot.press(".", "p", "o", "r", "t")
        await pilot.press("enter")
        await pilot.pause(0.25)

        assert calls[-1].display_filter == "tcp.port"


@pytest.mark.asyncio
async def test_live_display_filter_shows_tshark_field_hint() -> None:
    controller = FakeController(events=(LivePacketsAdded((tcp_packet(1),)),))
    app = LiveCaptureApp(
        "en0",
        controller,
        query_packets,
        read_details,
        display_filter_fields=("tcp", "tcp.port", "tcp.srcport", "udp"),
    )

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f", "t", "c")

        status = status_text(app, "#filter-status")
        assert "Подсказка:" in status
        assert "tcp.port" in status


@pytest.mark.asyncio
async def test_live_display_filter_shows_dropdown_suggestions_from_first_symbol() -> (
    None
):
    controller = FakeController(events=(LivePacketsAdded((tcp_packet(1),)),))
    app = LiveCaptureApp(
        "en0",
        controller,
        query_packets,
        read_details,
        display_filter_fields=("dns", "tcp", "tcp.port", "tcp.srcport", "udp"),
    )

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f", "t")
        suggestions = app.query_one("#filter-suggestions", OptionList)

        assert suggestions.display is True
        assert suggestions.option_count == 3
        assert str(suggestions.get_option_at_index(1).prompt) == "tcp.port ="

        await pilot.press("c", "p", ".")

        assert suggestions.option_count == 2
        assert str(suggestions.get_option_at_index(0).prompt) == "tcp.port ="


@pytest.mark.asyncio
async def test_live_display_filter_marks_input_valid_after_successful_query() -> None:
    controller = FakeController(events=(LivePacketsAdded((tcp_packet(1),)),))

    def successful_query(_query: PacketQuery) -> PacketQueryResult:
        return PacketQueryResult((tcp_packet(1),), None)

    app = LiveCaptureApp("en0", controller, successful_query, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f", "t", "c", "p", "enter")
        await pilot.pause(0.25)

        display_filter = app.query_one("#display-filter", Input)
        assert display_filter.has_class("filter-valid")
        assert not display_filter.has_class("filter-invalid")


@pytest.mark.asyncio
async def test_live_display_filter_marks_input_invalid_after_tshark_error() -> None:
    controller = FakeController(events=(LivePacketsAdded((tcp_packet(1),)),))

    def failing_query(_query: PacketQuery) -> PacketQueryResult:
        return PacketQueryResult((), "Syntax error")

    app = LiveCaptureApp("en0", controller, failing_query, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f", "t", "c", "p", " ", "&", "&", "enter")
        await pilot.pause(0.25)

        display_filter = app.query_one("#display-filter", Input)
        assert display_filter.has_class("filter-invalid")
        assert not display_filter.has_class("filter-valid")


@pytest.mark.asyncio
async def test_live_display_filter_marks_unknown_field_invalid_while_typing() -> None:
    controller = FakeController(events=(LivePacketsAdded((tcp_packet(1),)),))
    app = LiveCaptureApp(
        "en0",
        controller,
        query_packets,
        read_details,
        display_filter_fields=("tcp", "tcp.port", "tcp.srcport", "udp"),
    )

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f")
        await pilot.press(*tuple("tcp.dddsdsddsvv"))
        await pilot.pause(0.1)

        display_filter = app.query_one("#display-filter", Input)
        assert display_filter.has_class("filter-invalid")
        assert not display_filter.has_class("filter-valid")


@pytest.mark.asyncio
async def test_live_app_has_interface_selector_and_no_info_search() -> None:
    controller = FakeController()
    app = LiveCaptureApp(
        "en0",
        controller,
        query_packets,
        read_details,
        available_interfaces=("en0", "lo0"),
    )

    async with app.run_test() as pilot:
        await pilot.pause(0.12)

        selector = app.query_one("#interface-select", Select)
        assert selector.value == "en0"
        assert not app.query("#info-search")


@pytest.mark.asyncio
async def test_live_app_switches_interface_with_fresh_runtime() -> None:
    first = FakeController(events=(LivePacketsAdded((packet(1, "старый"),)),))
    second = FakeController(events=(LivePacketsAdded((packet(1, "новый"),)),))
    created: list[str] = []

    def runtime_factory(interface: str) -> LiveCaptureRuntime:
        created.append(interface)
        return LiveCaptureRuntime(second, query_packets, read_details)

    app = LiveCaptureApp(
        "en0",
        first,
        query_packets,
        read_details,
        available_interfaces=("en0", "lo0"),
        runtime_factory=runtime_factory,
    )

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        app.query_one("#display-filter", Input).value = "tcp"

        app.query_one("#interface-select", Select).value = "lo0"
        await pilot.pause(0.12)

        table = app.query_one("#packets", DataTable)
        assert created == ["lo0"]
        assert first.commands == ["quit"]
        assert first.joined
        assert second.started
        assert app.query_one("#display-filter", Input).value == ""
        assert table.row_count == 1
        assert str(table.get_row_at(0)[-1]) == "новый"


@pytest.mark.asyncio
async def test_live_filter_buttons_use_distinct_variants_and_labels() -> None:
    controller = FakeController()
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test():
        apply_button = app.query_one("#apply-filter", Button)
        clear_button = app.query_one("#clear-filter", Button)

        assert str(apply_button.label) == "Apply"
        assert apply_button.variant == "primary"
        assert str(clear_button.label) == "Cancel"
        assert clear_button.variant == "warning"


@pytest.mark.asyncio
async def test_live_filter_buttons_apply_and_clear_display_filter() -> None:
    calls: list[PacketQuery] = []

    def recording_query(query: PacketQuery) -> PacketQueryResult:
        calls.append(query)
        return PacketQueryResult((packet(1),), None)

    controller = FakeController(events=(LivePacketsAdded((packet(1),)),))
    app = LiveCaptureApp("en0", controller, recording_query, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f", "d", "n", "s")
        await pilot.click("#apply-filter")
        await pilot.pause(0.25)
        assert calls[-1].display_filter == "dns"

        await pilot.click("#clear-filter")
        await pilot.pause(0.25)

        assert app.query_one("#display-filter", Input).value == ""
        assert len(calls) == 1
        assert app.query_one("#packets", DataTable).row_count == 1


@pytest.mark.asyncio
async def test_live_display_filter_error_is_human_readable() -> None:
    controller = FakeController(events=(LivePacketsAdded((tcp_packet(1),)),))

    def failing_query(_query: PacketQuery) -> PacketQueryResult:
        return PacketQueryResult(
            (),
            'tshark: "TCP" is not a valid protocol or protocol field.\n'
            "    TCP\n"
            "    ^~~",
        )

    app = LiveCaptureApp("en0", controller, failing_query, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f", "T", "C", "P", "enter")
        await pilot.pause(0.25)

        status = status_text(app, "#filter-status")
        assert "Невалидный display filter" in status
        assert "`tcp`" in status
        assert "tshark:" not in status


@pytest.mark.asyncio
async def test_restart_clears_packets_from_previous_capture() -> None:
    controller = FakeController(
        events=(
            LiveStateChanged(CaptureState.STOPPED, 1, 72),
            LivePacketsAdded((packet(1, info="старый"),)),
        )
    )
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("r")
        controller.publish(
            LiveStateChanged(CaptureState.RUNNING, 0, 0, generation=1),
            LivePacketsAdded((packet(1, info="новый"),), generation=1),
        )
        await pilot.pause(0.11)

        table = app.query_one("#packets", DataTable)
        assert table.row_count == 1
        assert str(table.get_row_at(0)[-1]) == "новый"


@pytest.mark.asyncio
async def test_restart_ignores_controller_packets_queued_before_acknowledgement() -> (
    None
):
    controller = FakeController(events=(LiveStateChanged(CaptureState.STOPPED, 0, 0),))
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        controller.publish(LivePacketsAdded((packet(1, info="старый"),)))
        await pilot.press("r")
        await pilot.pause(0.11)

        assert app.query_one("#packets", DataTable).row_count == 0

        controller.publish(
            LiveStateChanged(CaptureState.RUNNING, 0, 0, generation=1),
            LivePacketsAdded((packet(1, info="новый"),), generation=1),
        )
        await pilot.pause(0.11)

        table = app.query_one("#packets", DataTable)
        assert table.row_count == 1
        assert str(table.get_row_at(0)[-1]) == "новый"


@pytest.mark.asyncio
async def test_restart_ignores_stale_state_followed_by_stale_packet() -> None:
    controller = FakeController(
        events=(LiveStateChanged(CaptureState.STOPPED, 0, 0, generation=0),)
    )
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("r")
        controller.publish(
            LiveStateChanged(CaptureState.STOPPED, 1, 72, generation=0),
            LivePacketsAdded((packet(1, info="старый"),), generation=0),
            LiveStateChanged(CaptureState.RUNNING, 0, 0, generation=1),
            LivePacketsAdded((packet(1, info="новый"),), generation=1),
        )
        await pilot.pause(0.11)

        table = app.query_one("#packets", DataTable)
        assert table.row_count == 1
        assert str(table.get_row_at(0)[-1]) == "новый"


@pytest.mark.asyncio
async def test_failed_restart_acknowledges_generation_and_updates_failed_state() -> (
    None
):
    controller = FakeController(
        events=(LiveStateChanged(CaptureState.STOPPED, 1, 72, generation=0),)
    )
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("r")
        controller.publish(
            LiveFailure("не удалось перезапустить захват", generation=1),
            LiveStateChanged(CaptureState.FAILED, 1, 72, generation=1),
        )
        await pilot.pause(0.11)

        assert status_text(app) == "не удалось перезапустить захват"
        assert "ошибка" in status_text(app, "#capture-status")

        await pilot.press("c")
        assert controller.commands == ["restart"]


@pytest.mark.asyncio
async def test_successful_restart_discards_failure_from_old_generation() -> None:
    controller = FakeController(
        events=(LiveStateChanged(CaptureState.STOPPED, 0, 0, generation=0),)
    )
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("r")
        controller.publish(
            LiveStateChanged(CaptureState.RUNNING, 0, 0, generation=1),
            LiveFailure("устаревшая ошибка", generation=0),
        )
        await pilot.pause(0.11)

        assert status_text(app) != "устаревшая ошибка"


@pytest.mark.asyncio
async def test_state_action_is_blocked_until_controller_reports_state() -> None:
    controller = FakeController()
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.press("c")

        assert controller.commands == []
        assert status_text(app) == "Состояние захвата ещё не получено."


@pytest.mark.asyncio
async def test_live_app_starts_controller_and_shows_state() -> None:
    controller = FakeController(
        events=(LiveStateChanged(CaptureState.RUNNING, packets=7, size=4096),)
    )
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)

        assert controller.started
        assert "выполняется" in status_text(app, "#capture-status")
        assert "7" in status_text(app, "#capture-status")
        assert "4096" in status_text(app, "#capture-status")


@pytest.mark.asyncio
async def test_s_submits_stop_and_save_only_while_running() -> None:
    controller = FakeController(
        events=(LiveStateChanged(CaptureState.RUNNING, packets=0, size=0),)
    )
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("s")

        assert controller.commands == ["stop_and_save"]


@pytest.mark.asyncio
async def test_invalid_stop_does_not_submit_and_shows_russian_status() -> None:
    controller = FakeController(
        events=(LiveStateChanged(CaptureState.STOPPED, packets=0, size=0),)
    )
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("s")

        assert controller.commands == []
        assert status_text(app) == "Остановить можно только запущенный захват."


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("state", "expected_commands"),
    [
        (CaptureState.STOPPED, ["continue"]),
        (CaptureState.RUNNING, []),
        (CaptureState.FAILED, []),
        (CaptureState.LIMIT_REACHED, []),
    ],
)
async def test_c_is_available_only_while_stopped(
    state: CaptureState, expected_commands: list[LiveCommand]
) -> None:
    controller = FakeController(events=(LiveStateChanged(state, 0, 0),))
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("c")

        assert controller.commands == expected_commands
        if not expected_commands:
            assert "остановлен" in status_text(app).lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("state", "expected_commands"),
    [
        (CaptureState.STOPPED, ["restart"]),
        (CaptureState.FAILED, ["restart"]),
        (CaptureState.LIMIT_REACHED, ["restart"]),
        (CaptureState.RUNNING, []),
    ],
)
async def test_r_is_available_in_restartable_states(
    state: CaptureState, expected_commands: list[LiveCommand]
) -> None:
    controller = FakeController(events=(LiveStateChanged(state, 0, 0),))
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("r")

        assert controller.commands == expected_commands
        if not expected_commands:
            assert "перезапуск" in status_text(app).lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("state", "expected_commands"),
    [
        (CaptureState.RUNNING, ["save"]),
        (CaptureState.STOPPED, ["save"]),
        (CaptureState.LIMIT_REACHED, ["save"]),
        (CaptureState.FAILED, []),
    ],
)
async def test_w_submits_snapshot_only_in_savable_states(
    state: CaptureState, expected_commands: list[LiveCommand]
) -> None:
    controller = FakeController(events=(LiveStateChanged(state, 0, 0),))
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("w")

        assert controller.commands == expected_commands
        if not expected_commands:
            assert "сохран" in status_text(app).lower()


@pytest.mark.asyncio
async def test_q_exits_and_closes_controller() -> None:
    controller = FakeController()
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.press("q")

    assert controller.commands == ["quit"]
    assert controller.joined


@pytest.mark.asyncio
async def test_live_saved_for_analysis_exits_with_path() -> None:
    saved = Path("/tmp/capture.pcapng")
    controller = FakeController(events=(LiveSaved(saved, True),))
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)

    assert app.return_value == saved


@pytest.mark.asyncio
async def test_snapshot_stays_open_and_shows_saved_path() -> None:
    saved = Path("/tmp/snapshot.pcapng")
    controller = FakeController(events=(LiveSaved(saved, False),))
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)

        assert app.is_running
        assert str(saved) in status_text(app)


@pytest.mark.asyncio
async def test_failure_keeps_packets_and_shows_message() -> None:
    controller = FakeController(
        events=(
            LivePacketsAdded((packet(1),)),
            LiveFailure("dumpcap завершился с ошибкой"),
        )
    )
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)

        assert app.query_one("#packets", DataTable).row_count == 1
        assert status_text(app) == "dumpcap завершился с ошибкой"


@pytest.mark.asyncio
async def test_live_app_focuses_and_clears_filters() -> None:
    controller = FakeController()
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test() as pilot:
        await pilot.press("f", "u", "d", "p")
        display_filter = app.query_one("#display-filter", Input)
        assert app.focused is display_filter

        await pilot.press("escape")
        assert display_filter.value == ""


@pytest.mark.asyncio
async def test_display_filter_error_keeps_previous_rows() -> None:
    controller = FakeController(events=(LivePacketsAdded((packet(1),)),))

    def failing_query(_query: PacketQuery) -> PacketQueryResult:
        return PacketQueryResult((), "Синтаксическая ошибка display filter")

    app = LiveCaptureApp("en0", controller, failing_query, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f", "u", "d", "p", " ", "&", "&")
        await pilot.press("enter")
        await pilot.pause(0.25)

        table = app.query_one("#packets", DataTable)
        assert table.row_count == 1
        assert next(str(value) for value in table.get_row_at(0)) == "1"
        assert status_text(app, "#filter-status") == (
            "Синтаксическая ошибка display filter"
        )


@pytest.mark.asyncio
async def test_details_reader_receives_global_packet_number() -> None:
    numbers: list[int] = []

    def recording_reader(number: int) -> PacketDetails:
        numbers.append(number)
        return PacketDetails(f"Frame {number}", "0000  aa")

    controller = FakeController(events=(LivePacketsAdded((packet(41), packet(82))),))
    app = LiveCaptureApp("en0", controller, query_packets, recording_reader)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("down")

        assert numbers == [41, 82]


@pytest.mark.asyncio
async def test_live_details_and_bytes_are_shown_in_separate_panes() -> None:
    controller = FakeController(events=(LivePacketsAdded((packet(1),)),))
    app = LiveCaptureApp(
        "en0",
        controller,
        query_packets,
        lambda _number: PacketDetails("Frame 1\nEthernet II", "0000  aa bb"),
    )

    async with app.run_test() as pilot:
        await pilot.pause(0.12)

        details = str(app.query_one("#details-content", Static).renderable)
        packet_bytes = str(app.query_one("#bytes-content", Static).renderable)
        assert "PACKET DETAILS" in details
        assert "Frame 1" in details
        assert "0000  aa bb" not in details
        assert "PACKET BYTES" in packet_bytes
        assert "0000  aa bb" in packet_bytes


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("size", "expected_columns"),
    [
        ((80, 24), ["No.", "Source", "Protocol", "Info"]),
        (
            (120, 24),
            ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"],
        ),
    ],
)
async def test_live_layout_uses_shared_width_boundaries(
    size: tuple[int, int], expected_columns: list[str]
) -> None:
    controller = FakeController(events=(LivePacketsAdded((packet(1),)),))
    app = LiveCaptureApp("en0", controller, query_packets, read_details)

    async with app.run_test(size=size) as pilot:
        await pilot.pause(0.12)
        table = app.query_one("#packets", DataTable)

        assert app.query_one("#size-warning", Static).display is False
        assert [str(column.label) for column in table.ordered_columns] == (
            expected_columns
        )


@pytest.mark.asyncio
async def test_live_layout_warns_below_minimum_and_details_scroll() -> None:
    long_tree = "\n".join(f"Протокол {number}" for number in range(80))
    controller = FakeController(events=(LivePacketsAdded((packet(1),)),))
    app = LiveCaptureApp(
        "en0",
        controller,
        query_packets,
        lambda _number: PacketDetails(long_tree, "0000  aa"),
    )

    async with app.run_test(size=(79, 23)) as pilot:
        await pilot.pause(0.12)
        details = app.query_one("#details", VerticalScroll)

        assert app.query_one("#size-warning", Static).display is True
        assert details.can_focus
        details.focus()
        await pilot.press("end")
        assert details.max_scroll_y > 0
        assert details.scroll_y == details.max_scroll_y
