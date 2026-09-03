"""Потоковый контроллер live-захвата без блокировок в интерфейсе."""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypeAlias

from wispwire.capture import CaptureError, CaptureSession, CaptureState
from wispwire.live_source import LivePacketSource
from wispwire.packets import PacketSummary
from wispwire.sessions import SessionSafetyError
from wispwire.tshark import TsharkReadError


@dataclass(frozen=True)
class LivePacketsAdded:
    """Пакеты, добавленные за одну итерацию контроллера."""

    packets: tuple[PacketSummary, ...]
    generation: int = 0


@dataclass(frozen=True)
class LiveStateChanged:
    """Текущее состояние захвата и подтверждённые объёмы."""

    state: CaptureState
    packets: int
    size: int
    generation: int = 0


@dataclass(frozen=True)
class LiveSaved:
    """Снимок захвата сохранён в указанный файл."""

    path: Path
    open_in_file_tui: bool


@dataclass(frozen=True)
class LiveFailure:
    """Операция захвата завершилась ожидаемой ошибкой."""

    message: str
    generation: int = 0


LiveEvent: TypeAlias = LivePacketsAdded | LiveStateChanged | LiveSaved | LiveFailure
LiveCommand: TypeAlias = Literal["stop_and_save", "continue", "restart", "save", "quit"]


class LiveCaptureController:
    """Единственный поток-владелец CaptureSession и LivePacketSource."""

    def __init__(
        self,
        capture: CaptureSession,
        source: LivePacketSource,
        *,
        destination_factory: Callable[[], Path] | None = None,
        poll_interval: float = 0.25,
    ) -> None:
        self._capture = capture
        self._source = source
        self._destination_factory = destination_factory or _default_destination
        self._poll_interval = poll_interval
        self._commands: queue.SimpleQueue[LiveCommand] = queue.SimpleQueue()
        self._events: queue.SimpleQueue[LiveEvent] = queue.SimpleQueue()
        self._thread: threading.Thread | None = None
        self._generation = 0
        self._terminal_error: BaseException | None = None

    def start(self) -> None:
        """Запускает неблокирующий поток управления захватом."""
        if self._thread is not None:
            raise RuntimeError("контроллер live-захвата уже запущен")
        self._thread = threading.Thread(target=self._run, name="wispwire-live-capture")
        self._thread.start()

    def submit(self, command: LiveCommand) -> None:
        """Помещает команду в очередь, не ожидая поток захвата."""
        self._commands.put(command)

    def drain_events(self) -> tuple[LiveEvent, ...]:
        """Неблокирующе возвращает все уже опубликованные события."""
        events: list[LiveEvent] = []
        while True:
            try:
                events.append(self._events.get_nowait())
            except queue.Empty:
                return tuple(events)

    def join(self) -> None:
        """Ожидает завершения потока контроллера."""
        if self._thread is not None:
            self._thread.join()
        if self._terminal_error is not None:
            raise CaptureError(
                f"не удалось безопасно закрыть live-захват: {self._terminal_error}"
            ) from self._terminal_error

    def _run(self) -> None:
        try:
            try:
                self._capture.start()
                self._publish_state()
            except (CaptureError, OSError) as error:
                self._fail(error)

            while True:
                if self._process_commands():
                    return
                if self._capture.state in (CaptureState.RUNNING, CaptureState.STOPPED):
                    try:
                        segments = self._capture.collect_closed_segments()
                        packets = self._source.ingest(segments)
                        if packets:
                            self._events.put(
                                LivePacketsAdded(packets, self._generation)
                            )
                        self._publish_state()
                    except (CaptureError, OSError, TsharkReadError) as error:
                        self._fail(error)
                threading.Event().wait(self._poll_interval)
        finally:
            self._close_resources()

    def _process_commands(self) -> bool:
        while True:
            try:
                command = self._commands.get_nowait()
            except queue.Empty:
                return False

            if command == "quit":
                return True
            try:
                self._process_command(command)
            except (CaptureError, OSError, SessionSafetyError) as error:
                self._fail(error)

    def _process_command(self, command: LiveCommand) -> None:
        if command == "continue":
            if self._capture.state is CaptureState.LIMIT_REACHED:
                raise CaptureError("нельзя продолжить захват: достигнут лимит размера")
            self._capture.continue_capture()
        elif command == "restart":
            try:
                self._capture.restart()
            except (CaptureError, OSError) as error:
                self._generation += 1
                self._capture.state = CaptureState.FAILED
                self._fail(error)
                return
            try:
                self._source.reset()
            except (OSError, SessionSafetyError) as error:
                failure: CaptureError | OSError | SessionSafetyError = error
                try:
                    if self._capture.state is CaptureState.RUNNING:
                        self._capture.stop()
                except (CaptureError, OSError) as stop_error:
                    failure = CaptureError(
                        "не удалось сбросить индекс live-захвата; "
                        f"дополнительно не удалось остановить новый захват: {stop_error}"
                    )
                self._generation += 1
                self._capture.state = CaptureState.FAILED
                self._fail(failure)
                return
            self._generation += 1
        elif command == "save":
            destination = self._destination_factory()
            self._capture.save(destination)
            self._events.put(LiveSaved(destination, False))
        elif command == "stop_and_save":
            destination = self._destination_factory()
            self._capture.stop()
            self._capture.save(destination)
            self._events.put(LiveSaved(destination, True))
        self._publish_state()

    def _publish_state(self) -> None:
        self._events.put(
            LiveStateChanged(
                self._capture.state,
                self._source.packet_count,
                self._capture.confirmed_size,
                self._generation,
            )
        )

    def _fail(
        self, error: CaptureError | OSError | SessionSafetyError | TsharkReadError
    ) -> None:
        self._events.put(LiveFailure(str(error), self._generation))
        self._publish_state()

    def _close_resources(self) -> None:
        terminal_error: BaseException | None = None
        try:
            self._source.close()
        except (CaptureError, OSError, SessionSafetyError) as error:
            terminal_error = error
        try:
            self._capture.close()
        except (CaptureError, OSError, SessionSafetyError) as error:
            if terminal_error is None:
                terminal_error = error
        self._terminal_error = terminal_error


def _default_destination() -> Path:
    """Возвращает путь, который пользователь выбирает до отправки команды."""
    raise CaptureError("не задан путь для сохранения live-захвата")
