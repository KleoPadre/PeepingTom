import threading
from pathlib import Path
from typing import Literal

import pytest
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Input, Static

from wispwire.capture import CaptureState
from wispwire.file_source import PacketQuery, PacketQueryResult
from wispwire.live_controller import (
    LiveEvent,
    LiveFailure,
    LivePacketsAdded,
    LiveSaved,
    LiveStateChanged,
)
from wispwire.live_tui import LiveCaptureApp
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
        await pilot.pause(0.25)

        assert len(callback_threads) == 2
        assert all(thread is not threading.main_thread() for thread in callback_threads)


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

        app.query_one("#packets", DataTable).focus()
        await pilot.press("/", "d", "n", "s")
        info_search = app.query_one("#info-search", Input)
        assert app.focused is info_search

        await pilot.press("escape")
        assert info_search.value == ""


@pytest.mark.asyncio
async def test_display_filter_error_keeps_previous_rows() -> None:
    controller = FakeController(events=(LivePacketsAdded((packet(1),)),))

    def failing_query(_query: PacketQuery) -> PacketQueryResult:
        return PacketQueryResult((), "Синтаксическая ошибка display filter")

    app = LiveCaptureApp("en0", controller, failing_query, read_details)

    async with app.run_test() as pilot:
        await pilot.pause(0.12)
        await pilot.press("f", "u", "d", "p", " ", "&", "&")
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
