from __future__ import annotations

import threading
import time
from pathlib import Path

from wispwire.capture import CaptureError, CaptureState
from wispwire.live_controller import (
    LiveCaptureController,
    LiveFailure,
    LivePacketsAdded,
    LiveSaved,
    LiveStateChanged,
)
from wispwire.packets import PacketSummary


def packet(number: int) -> PacketSummary:
    return PacketSummary(
        number, "0.000000", "192.0.2.1", "192.0.2.53", "DNS", 74, "Запрос"
    )


def wait_until(condition: object, timeout: float = 1.0) -> bool:
    assert callable(condition)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return bool(condition())


class FakeCapture:
    def __init__(self, *, segments: tuple[Path, ...] = ()) -> None:
        self.segments = segments
        self.state = CaptureState.STOPPED
        self.confirmed_size = 12
        self.calls: list[str] = []
        self.thread_ids: list[int] = []
        self.collect_error: CaptureError | None = None

    def _call(self, name: str) -> None:
        self.calls.append(name)
        self.thread_ids.append(threading.get_ident())

    def start(self) -> None:
        self._call("start")
        self.state = CaptureState.RUNNING

    def collect_closed_segments(self) -> tuple[Path, ...]:
        self._call("collect")
        if self.collect_error is not None:
            raise self.collect_error
        return self.segments

    def stop(self) -> None:
        self._call("stop")
        self.state = CaptureState.STOPPED

    def continue_capture(self) -> None:
        self._call("continue")
        self.state = CaptureState.RUNNING

    def restart(self) -> None:
        self._call("restart")
        self.state = CaptureState.RUNNING

    def save(self, destination: Path) -> Path:
        self._call(f"save:{destination.name}")
        return destination

    def close(self) -> bool:
        self._call("close")
        self.state = CaptureState.CLOSED
        return True


class FakeSource:
    def __init__(
        self, packets: dict[tuple[Path, ...], tuple[PacketSummary, ...]]
    ) -> None:
        self.packets = packets
        self.packet_count = 0
        self.calls: list[str] = []
        self.thread_ids: list[int] = []

    def _call(self, name: str) -> None:
        self.calls.append(name)
        self.thread_ids.append(threading.get_ident())

    def ingest(self, segments: tuple[Path, ...]) -> tuple[PacketSummary, ...]:
        self._call("ingest")
        added = self.packets.get(segments, ())
        self.packet_count += len(added)
        return added

    def reset(self) -> None:
        self._call("reset")
        self.packet_count = 0

    def close(self) -> None:
        self._call("close")


def events_until(controller: LiveCaptureController, predicate: object) -> list[object]:
    assert callable(predicate)
    events: list[object] = []

    def received() -> bool:
        events.extend(controller.drain_events())
        return bool(predicate(events))

    assert wait_until(received)
    return events


def test_controller_publishes_one_batch_for_new_closed_segments(tmp_path: Path) -> None:
    capture = FakeCapture(segments=(tmp_path / "one.pcapng", tmp_path / "two.pcapng"))
    source = FakeSource({capture.segments: (packet(1), packet(2))})
    controller = LiveCaptureController(capture, source, poll_interval=0.001)

    controller.start()
    events = events_until(
        controller,
        lambda items: any(isinstance(item, LivePacketsAdded) for item in items),
    )
    controller.submit("quit")
    controller.join()

    batches = [item for item in events if isinstance(item, LivePacketsAdded)]
    assert batches == [LivePacketsAdded((packet(1), packet(2)))]
    assert capture.calls[:2] == ["start", "collect"]
    assert capture.calls[-1] == "close"
    assert source.calls[-1] == "close"


def test_controller_runs_commands_in_queue_order_on_one_thread(tmp_path: Path) -> None:
    capture = FakeCapture()
    source = FakeSource({})
    destinations = iter((tmp_path / "one.pcapng", tmp_path / "two.pcapng"))
    controller = LiveCaptureController(
        capture,
        source,
        destination_factory=lambda: next(destinations),
        poll_interval=0.05,
    )

    controller.start()
    assert wait_until(lambda: capture.calls)
    capture.state = CaptureState.STOPPED
    controller.submit("continue")
    controller.submit("stop_and_save")
    controller.submit("restart")
    controller.submit("save")
    events_until(
        controller,
        lambda items: sum(isinstance(item, LiveSaved) for item in items) == 2,
    )
    controller.submit("quit")
    controller.join()

    commands = [call for call in capture.calls if call != "collect"]
    assert commands == [
        "start",
        "continue",
        "stop",
        "save:one.pcapng",
        "restart",
        "save:two.pcapng",
        "close",
    ]
    assert source.calls.count("reset") == 1
    assert source.calls[-1] == "close"
    assert len(set(capture.thread_ids + source.thread_ids)) == 1


def test_controller_reports_failure_without_continue_at_size_limit() -> None:
    capture = FakeCapture()
    capture.state = CaptureState.LIMIT_REACHED
    source = FakeSource({})
    controller = LiveCaptureController(capture, source, poll_interval=0.05)

    controller.start()
    assert wait_until(lambda: capture.calls)
    capture.state = CaptureState.LIMIT_REACHED
    controller.submit("continue")
    events = events_until(
        controller, lambda items: any(isinstance(item, LiveFailure) for item in items)
    )
    controller.submit("quit")
    controller.join()

    assert "continue" not in capture.calls
    assert any(
        "лимит" in item.message for item in events if isinstance(item, LiveFailure)
    )


def test_controller_resets_source_before_restart_numbering() -> None:
    capture = FakeCapture()
    source = FakeSource({})
    controller = LiveCaptureController(capture, source, poll_interval=0.05)

    controller.start()
    assert wait_until(lambda: capture.calls)
    capture.state = CaptureState.STOPPED
    controller.submit("restart")
    assert events_until(
        controller,
        lambda items: any(isinstance(item, LiveStateChanged) for item in items),
    )
    controller.submit("quit")
    controller.join()

    assert source.calls.index("reset") < capture.calls.index("restart")


def test_controller_closes_once_after_collect_error() -> None:
    capture = FakeCapture()
    capture.collect_error = CaptureError("сломанный сегмент")
    source = FakeSource({})
    controller = LiveCaptureController(capture, source, poll_interval=0.001)

    controller.start()
    events = events_until(
        controller, lambda items: any(isinstance(item, LiveFailure) for item in items)
    )
    controller.submit("quit")
    controller.join()

    assert [item.message for item in events if isinstance(item, LiveFailure)] == [
        "сломанный сегмент"
    ]
    assert capture.calls.count("close") == 1
    assert source.calls.count("close") == 1
