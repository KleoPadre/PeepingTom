"""Управление процессом live-захвата dumpcap."""

from __future__ import annotations

import queue
import subprocess
import threading
from collections.abc import Callable, Iterable
from enum import StrEnum
from pathlib import Path
from select import select

from wispwire.sessions import Session, SessionSafetyError, SessionStorage


class CaptureState(StrEnum):
    """Состояние текущего live-захвата."""

    RUNNING = "running"
    STOPPED = "stopped"
    LIMIT_REACHED = "limit_reached"
    FAILED = "failed"
    CLOSED = "closed"


class CaptureError(RuntimeError):
    """Live-захват нельзя безопасно продолжить."""


def build_dumpcap_command(
    dumpcap_path: Path, interface: str, output_base: Path
) -> list[str]:
    """Строит команду dumpcap с сегментацией каждые полсекунды."""
    return [
        str(dumpcap_path),
        "-i",
        interface,
        "-w",
        str(output_base),
        "-b",
        "duration:0.5",
        "-b",
        "printname:stdout",
    ]


def build_mergecap_command(
    mergecap_path: Path, output_path: Path, segments: tuple[Path, ...]
) -> list[str]:
    """Строит команду mergecap для объединения сегментов."""
    return [
        str(mergecap_path),
        "-w",
        str(output_path),
        *(str(path) for path in segments),
    ]


class CaptureSession:
    """Запускает и останавливает один процесс dumpcap."""

    def __init__(
        self,
        dumpcap_path: Path,
        mergecap_path: Path,
        interface: str,
        *,
        storage: SessionStorage,
        max_size: int = 1_073_741_824,
        popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.dumpcap_path = dumpcap_path
        self.mergecap_path = mergecap_path
        self.interface = interface
        self.storage = storage
        self.max_size = max_size
        self._popen = popen
        self._run = run
        self._process: subprocess.Popen[str] | None = None
        self._stdout_lines: queue.SimpleQueue[str] = queue.SimpleQueue()
        self._stdout_reader: threading.Thread | None = None
        self.session: Session | None = None
        self._segments: list[Path] = []
        self.state = CaptureState.STOPPED

    def start(self) -> None:
        """Создаёт сессию и запускает dumpcap."""
        if self.state is not CaptureState.STOPPED or self.session is not None:
            raise CaptureError("захват можно запустить только из исходного состояния")

        self.session = self.storage.create_session()
        command = build_dumpcap_command(
            self.dumpcap_path, self.interface, self.session.path / "segment"
        )
        try:
            self._process = self._popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as error:
            self.state = CaptureState.FAILED
            raise CaptureError("не удалось запустить dumpcap") from error
        self._start_stdout_reader()
        self.state = CaptureState.RUNNING

    @property
    def segments(self) -> tuple[Path, ...]:
        """Возвращает подтверждённые закрытые сегменты захвата."""
        return tuple(self._segments)

    def collect_closed_segments(self) -> tuple[Path, ...]:
        """Регистрирует безопасно завершённые dumpcap сегменты из stdout."""
        if self.state not in (CaptureState.RUNNING, CaptureState.STOPPED):
            raise CaptureError("читать сегменты можно только у запущенного захвата")
        if self._process is None:
            raise CaptureError("для захвата недоступен процесс")
        if self.session is None or self._process.stdout is None:
            self.state = CaptureState.FAILED
            raise CaptureError("для захвата недоступна сессия или stdout")

        for line in self._closed_segment_lines():
            segment = Path(line.strip())
            if not self._is_safe_segment(segment):
                self.state = CaptureState.FAILED
                raise CaptureError("сегмент выходит за пределы сессии или небезопасен")
            if segment in self._segments:
                continue
            try:
                self.session = self.storage.register_file(self.session, segment)
                size = self.storage.session_size(self.session)
            except (OSError, SessionSafetyError) as error:
                self.state = CaptureState.FAILED
                raise CaptureError(
                    "не удалось безопасно зарегистрировать сегмент"
                ) from error
            self._segments.append(segment)
            if size > self.max_size:
                self.stop()
                self.state = CaptureState.LIMIT_REACHED
                break
        return self.segments

    def continue_capture(self) -> None:
        """Продолжает остановленный захват в уже созданной сессии."""
        if self.state is CaptureState.LIMIT_REACHED:
            raise CaptureError("нельзя продолжить захват: достигнут лимит размера")
        if self.state is not CaptureState.STOPPED or self.session is None:
            raise CaptureError("продолжить можно только остановленный захват")

        command = build_dumpcap_command(
            self.dumpcap_path, self.interface, self.session.path / "segment"
        )
        try:
            self._process = self._popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as error:
            self.state = CaptureState.FAILED
            raise CaptureError("не удалось запустить dumpcap") from error
        self._start_stdout_reader()
        self.state = CaptureState.RUNNING

    def stop(self) -> None:
        """Останавливает dumpcap и проверяет код завершения."""
        if self.state is not CaptureState.RUNNING or self._process is None:
            raise CaptureError("остановить можно только запущенный захват")

        self._process.terminate()
        returncode = self._process.wait()
        if returncode != 0:
            self.state = CaptureState.FAILED
            raise CaptureError(f"dumpcap завершился с кодом {returncode}")
        if self._stdout_reader is not None:
            self._stdout_reader.join()
        self.state = CaptureState.STOPPED

    def _is_safe_segment(self, segment: Path) -> bool:
        """Проверяет, что сегмент — обычный файл внутри текущей сессии."""
        assert self.session is not None
        try:
            segment.resolve().relative_to(self.session.path.resolve())
        except (OSError, ValueError):
            return False
        return (
            segment.exists()
            and not segment.is_symlink()
            and segment.is_file()
            and segment.stat().st_nlink == 1
        )

    def _closed_segment_lines(self) -> Iterable[str]:
        """Возвращает доступные строки stdout, не блокируя работающий захват."""
        assert self._process is not None
        assert self._process.stdout is not None
        if self._stdout_reader is not None:
            return self._queued_stdout_lines()
        stdout = self._process.stdout
        if self.state is CaptureState.STOPPED:
            return stdout
        try:
            stdout.fileno()
        except (AttributeError, OSError):
            return stdout

        lines: list[str] = []
        while select((stdout,), (), (), 0)[0]:
            line = stdout.readline()
            if not line:
                break
            lines.append(line)
        return lines

    def _start_stdout_reader(self) -> None:
        """Запускает фоновое чтение stdout настоящего процесса dumpcap."""
        assert self._process is not None
        stdout = self._process.stdout
        if stdout is None:
            return
        try:
            stdout.fileno()
        except (AttributeError, OSError):
            return
        self._stdout_lines = queue.SimpleQueue()
        self._stdout_reader = threading.Thread(
            target=self._read_stdout,
            args=(stdout,),
            daemon=True,
        )
        self._stdout_reader.start()

    def _read_stdout(self, stdout: Iterable[str]) -> None:
        """Передаёт строки stdout в очередь, не блокируя вызывающий код."""
        try:
            for line in stdout:
                self._stdout_lines.put(line)
        except (OSError, ValueError):
            return

    def _queued_stdout_lines(self) -> tuple[str, ...]:
        """Извлекает уже полученные строки stdout без ожидания."""
        lines: list[str] = []
        while True:
            try:
                lines.append(self._stdout_lines.get_nowait())
            except queue.Empty:
                return tuple(lines)
