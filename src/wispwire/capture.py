"""Управление процессом live-захвата dumpcap."""

from __future__ import annotations

import os
import queue
import stat
import subprocess
import threading
from collections.abc import Callable, Iterable
from enum import StrEnum
from pathlib import Path

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
        self._stderr_lines: queue.SimpleQueue[str] = queue.SimpleQueue()
        self._stdout_reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None
        self._stdout_source: object | None = None
        self._stderr_source: object | None = None
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
        self._start_stream_readers()
        self.state = CaptureState.RUNNING

    @property
    def segments(self) -> tuple[Path, ...]:
        """Возвращает подтверждённые закрытые сегменты захвата."""
        return tuple(self._segments)

    @property
    def confirmed_size(self) -> int:
        """Возвращает размер текущей сессии с подтверждёнными сегментами."""
        return sum(segment.stat().st_size for segment in self._segments)

    def collect_closed_segments(self) -> tuple[Path, ...]:
        """Регистрирует безопасно завершённые dumpcap сегменты из stdout."""
        if self.state not in (CaptureState.RUNNING, CaptureState.STOPPED):
            raise CaptureError("читать сегменты можно только у запущенного захвата")
        if self._process is None:
            raise CaptureError("для захвата недоступен процесс")
        if self.session is None or self._process.stdout is None:
            self.state = CaptureState.FAILED
            raise CaptureError("для захвата недоступна сессия или stdout")

        self._ensure_stream_readers()
        try:
            limit_reached = self._register_closed_segment_lines(
                self._queued_stdout_lines()
            )
        except CaptureError:
            self._drain_after_capture_error()
            raise

        returncode = self._poll_process()
        if limit_reached and returncode is None:
            returncode = self._terminate_existing_process()
            limit_reached = (
                self._register_closed_segment_lines(self._queued_stdout_lines())
                or limit_reached
            )
        elif returncode is not None:
            self._wait_for_stream_readers()
            limit_reached = (
                self._register_closed_segment_lines(self._queued_stdout_lines())
                or limit_reached
            )

        if returncode is not None:
            if returncode != 0:
                self.state = CaptureState.FAILED
                raise CaptureError(self._dumpcap_error(returncode))
            self.state = (
                CaptureState.LIMIT_REACHED if limit_reached else CaptureState.STOPPED
            )
        return self.segments

    def continue_capture(self) -> None:
        """Продолжает остановленный захват в уже созданной сессии."""
        if self.state is CaptureState.LIMIT_REACHED:
            raise CaptureError("нельзя продолжить захват: достигнут лимит размера")
        if self.state is not CaptureState.STOPPED or self.session is None:
            raise CaptureError("продолжить можно только остановленный захват")

        self._ensure_stream_readers()
        self._wait_for_stream_readers()
        if self._register_closed_segment_lines(self._queued_stdout_lines()):
            self.state = CaptureState.LIMIT_REACHED
            raise CaptureError("нельзя продолжить захват: достигнут лимит размера")

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
        self._start_stream_readers()
        self.state = CaptureState.RUNNING

    def stop(self) -> None:
        """Останавливает dumpcap и проверяет код завершения."""
        if self.state is not CaptureState.RUNNING or self._process is None:
            raise CaptureError("остановить можно только запущенный захват")

        returncode = self._terminate_existing_process()
        assert returncode is not None
        try:
            limit_reached = self._register_closed_segment_lines(
                self._queued_stdout_lines()
            )
        except CaptureError:
            self.state = CaptureState.FAILED
            raise
        if returncode != 0:
            self.state = CaptureState.FAILED
            raise CaptureError(self._dumpcap_error(returncode))
        self.state = (
            CaptureState.LIMIT_REACHED if limit_reached else CaptureState.STOPPED
        )

    def save(self, destination: Path) -> Path:
        """Сохраняет подтверждённые сегменты в новый файл PCAPNG."""
        destination = Path(destination)
        if destination.exists():
            raise CaptureError("файл назначения уже существует")

        was_running = self.state is CaptureState.RUNNING
        if was_running:
            self.stop()
        if not self._segments:
            raise CaptureError("для сохранения нужен хотя бы один закрытый сегмент")

        temporary = destination.with_name(f"{destination.name}.part")
        temporary_fd: int | None = None
        temporary_identity: os.stat_result | None = None
        try:
            temporary_fd = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            temporary_identity = os.fstat(temporary_fd)
            result = self._run(
                build_mergecap_command(self.mergecap_path, temporary, self.segments),
                capture_output=True,
                text=True,
                check=False,
                shell=False,
            )
            if result.returncode != 0:
                error = result.stderr.strip() or (
                    f"mergecap завершился с кодом {result.returncode}"
                )
                raise CaptureError(error)
            if not self._is_expected_temporary(temporary, temporary_identity):
                raise CaptureError("временный файл .part был небезопасно подменён")
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError as error:
            if temporary_fd is None:
                raise CaptureError(
                    "временный файл .part уже существует или небезопасен"
                ) from error
            raise CaptureError("файл назначения уже существует") from error
        except OSError as error:
            raise CaptureError("не удалось сохранить снимок захвата") from error
        except CaptureError:
            raise
        finally:
            if temporary_fd is not None and temporary_identity is not None:
                self._unlink_owned_temporary(temporary, temporary_identity)
                os.close(temporary_fd)

        if was_running and self.state is CaptureState.STOPPED:
            self.continue_capture()
        return destination

    def restart(self) -> None:
        """Закрывает текущую сессию и запускает новую."""
        if self.state not in (
            CaptureState.STOPPED,
            CaptureState.FAILED,
            CaptureState.LIMIT_REACHED,
        ):
            raise CaptureError("перезапуск доступен только остановленному захвату")
        self._drain_before_cleanup()
        if self.session is not None and not self.storage.close_session(self.session):
            raise CaptureError("не удалось безопасно закрыть сессию захвата")

        self._process = None
        self._stdout_reader = None
        self._stderr_reader = None
        self._stdout_source = None
        self._stderr_source = None
        self.session = None
        self._segments.clear()
        self.state = CaptureState.STOPPED
        self.start()

    def close(self) -> bool:
        """Останавливает захват и закрывает только его собственную сессию."""
        if self.state is CaptureState.CLOSED:
            return True
        self._drain_before_cleanup()
        if self.session is not None and not self.storage.close_session(self.session):
            raise CaptureError("не удалось безопасно закрыть сессию захвата")

        self._process = None
        self._stdout_reader = None
        self._stderr_reader = None
        self._stdout_source = None
        self._stderr_source = None
        self.session = None
        self._segments.clear()
        self.state = CaptureState.CLOSED
        return True

    def _terminate_existing_process(self) -> int | None:
        """Завершает текущий процесс независимо от состояния захвата."""
        if self._process is None:
            return None
        self._ensure_stream_readers()
        if self._poll_process() is None:
            self._process.terminate()
        returncode = self._process.wait()
        self._wait_for_stream_readers()
        return returncode

    def _poll_process(self) -> int | None:
        """Возвращает код завершения без ожидания процесса."""
        assert self._process is not None
        return self._process.poll()

    def _drain_before_cleanup(self) -> None:
        """Дренирует вывод и регистрирует финальные сегменты до удаления сессии."""
        if self._process is None:
            return
        self._terminate_existing_process()
        self._register_closed_segment_lines(self._queued_stdout_lines())

    def _drain_after_capture_error(self) -> None:
        """Останавливает ошибочный процесс и дренирует его каналы без блокировки."""
        if self._process is None:
            return
        self._terminate_existing_process()

    def _register_closed_segment_lines(self, lines: Iterable[str]) -> bool:
        """Проверяет и регистрирует строки закрытых сегментов."""
        if self.session is None:
            self.state = CaptureState.FAILED
            raise CaptureError("для захвата недоступна сессия")

        limit_reached = False
        for line in lines:
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
            limit_reached = limit_reached or size > self.max_size
        return limit_reached

    def _dumpcap_error(self, returncode: int) -> str:
        """Возвращает stderr dumpcap либо сообщение с кодом завершения."""
        stderr = "".join(self._queued_stderr_lines()).strip()
        return stderr or f"dumpcap завершился с кодом {returncode}"

    @staticmethod
    def _is_expected_temporary(temporary: Path, expected: os.stat_result) -> bool:
        """Проверяет обычный .part, созданный текущим вызовом save()."""
        try:
            current = temporary.lstat()
        except OSError:
            return False
        return (
            stat.S_ISREG(current.st_mode)
            and current.st_dev == expected.st_dev
            and current.st_ino == expected.st_ino
            and current.st_nlink == 1
        )

    @classmethod
    def _unlink_owned_temporary(cls, temporary: Path, expected: os.stat_result) -> None:
        """Удаляет только всё ещё принадлежащий вызову обычный .part."""
        try:
            current = temporary.lstat()
        except OSError:
            return
        if not (
            stat.S_ISREG(current.st_mode)
            and current.st_dev == expected.st_dev
            and current.st_ino == expected.st_ino
        ):
            return
        try:
            temporary.unlink()
        except OSError:
            return

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

    def _start_stream_readers(self) -> None:
        """Запускает фоновые читатели stdout и stderr процесса dumpcap."""
        self._stdout_lines = queue.SimpleQueue()
        self._stderr_lines = queue.SimpleQueue()
        self._stdout_reader = None
        self._stderr_reader = None
        self._stdout_source = None
        self._stderr_source = None
        self._ensure_stream_readers()

    def _ensure_stream_readers(self) -> None:
        """Подключает неблокирующие читатели к текущим потокам процесса."""
        assert self._process is not None
        stdout = self._process.stdout
        if stdout is not None and stdout is not self._stdout_source:
            self._stdout_source = stdout
            self._stdout_reader = self._start_stream_reader(
                stdout, self._stdout_lines, "wispwire-dumpcap-stdout"
            )
        stderr = self._process.stderr
        if stderr is not None and stderr is not self._stderr_source:
            self._stderr_source = stderr
            self._stderr_reader = self._start_stream_reader(
                stderr, self._stderr_lines, "wispwire-dumpcap-stderr"
            )

    @staticmethod
    def _start_stream_reader(
        stream: Iterable[str], lines: queue.SimpleQueue[str], name: str
    ) -> threading.Thread:
        reader = threading.Thread(
            target=CaptureSession._read_stream,
            args=(stream, lines),
            name=name,
            daemon=True,
        )
        reader.start()
        return reader

    @staticmethod
    def _read_stream(stream: Iterable[str], lines: queue.SimpleQueue[str]) -> None:
        """Передаёт строки потока в очередь, не блокируя основной поток."""
        try:
            for line in stream:
                lines.put(line)
        except (OSError, ValueError):
            return

    def _wait_for_stream_readers(self) -> None:
        """Ждёт EOF обоих каналов после завершения dumpcap."""
        if self._stdout_reader is not None:
            self._stdout_reader.join()
        if self._stderr_reader is not None:
            self._stderr_reader.join()

    def _queued_stdout_lines(self) -> tuple[str, ...]:
        """Извлекает уже полученные строки stdout без ожидания."""
        if self._stdout_reader is not None:
            self._stdout_reader.join(timeout=0.01)
        return self._queued_lines(self._stdout_lines)

    def _queued_stderr_lines(self) -> tuple[str, ...]:
        """Извлекает уже полученные строки stderr без ожидания."""
        return self._queued_lines(self._stderr_lines)

    @staticmethod
    def _queued_lines(lines_queue: queue.SimpleQueue[str]) -> tuple[str, ...]:
        """Извлекает накопленные строки из указанной очереди."""
        lines: list[str] = []
        while True:
            try:
                lines.append(lines_queue.get_nowait())
            except queue.Empty:
                return tuple(lines)
