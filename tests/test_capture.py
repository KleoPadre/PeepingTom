from __future__ import annotations

import os
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from wispwire.capture import (
    CaptureError,
    CaptureSession,
    CaptureState,
    build_dumpcap_command,
    build_mergecap_command,
)
from wispwire.sessions import Session, SessionStorage


class _Process:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.terminated = False
        self.waited = False
        self.stdout: object | None = None

    def terminate(self) -> None:
        self.terminated = True

    def wait(self) -> int:
        self.waited = True
        return self.returncode


def completed(
    stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def started_capture(
    tmp_path: Path,
    *,
    max_size: int = 1_073_741_824,
    process: _Process | None = None,
) -> CaptureSession:
    capture = CaptureSession(
        Path("/opt/bin/dumpcap"),
        Path("/opt/bin/mergecap"),
        "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        max_size=max_size,
        popen=recording_popen([], process),
    )
    capture.start()
    return capture


def recording_popen(
    calls: list[tuple[tuple[object, ...], dict[str, object]]],
    process: _Process | None = None,
) -> Callable[..., _Process]:
    def popen(*args: object, **kwargs: object) -> _Process:
        calls.append((args, kwargs))
        return process or _Process()

    return popen


def stopped_capture_with_segment(
    tmp_path: Path,
    *,
    merge_result: subprocess.CompletedProcess[str] | None = None,
) -> CaptureSession:
    """Создаёт остановленный захват с одним подтверждённым сегментом."""

    def mergecap(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        result = merge_result or completed()
        Path(command[2]).write_bytes(b"partial")
        if result.returncode == 0:
            Path(command[2]).write_bytes(b"merged")
        return result

    process = _Process()
    capture = CaptureSession(
        Path("/opt/bin/dumpcap"),
        Path("/opt/bin/mergecap"),
        "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        popen=recording_popen([], process),
        run=mergecap,
    )
    capture.start()
    assert capture.session is not None
    segment = capture.session.path / "segment_00001_20260902000000.pcapng"
    segment.write_bytes(b"pcapng")
    process.stdout = iter([f"{segment}\n"])
    capture.stop()
    capture.collect_closed_segments()
    return capture


def test_build_dumpcap_command_segments_every_half_second(tmp_path: Path) -> None:
    assert build_dumpcap_command(
        Path("/opt/bin/dumpcap"), "en0", tmp_path / "segment"
    ) == [
        "/opt/bin/dumpcap",
        "-i",
        "en0",
        "-w",
        str(tmp_path / "segment"),
        "-b",
        "duration:0.5",
        "-b",
        "printname:stdout",
    ]


def test_build_mergecap_command_writes_all_segments_to_output(tmp_path: Path) -> None:
    assert build_mergecap_command(
        Path("/opt/bin/mergecap"),
        tmp_path / "capture.pcapng",
        (tmp_path / "segment_00001", tmp_path / "segment_00002"),
    ) == [
        "/opt/bin/mergecap",
        "-w",
        str(tmp_path / "capture.pcapng"),
        str(tmp_path / "segment_00001"),
        str(tmp_path / "segment_00002"),
    ]


def test_start_creates_session_and_starts_dumpcap(tmp_path: Path) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    capture = CaptureSession(
        Path("/opt/bin/dumpcap"),
        Path("/opt/bin/mergecap"),
        "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        popen=recording_popen(calls),
    )

    capture.start()

    assert capture.state is CaptureState.RUNNING
    assert capture.session is not None
    assert calls[0][0][0] == build_dumpcap_command(
        Path("/opt/bin/dumpcap"), "en0", capture.session.path / "segment"
    )
    assert calls[0][1] == {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }


def test_start_marks_capture_failed_when_dumpcap_cannot_start(tmp_path: Path) -> None:
    def unavailable_popen(*args: object, **kwargs: object) -> Any:
        raise OSError("dumpcap отсутствует")

    capture = CaptureSession(
        Path("/opt/bin/dumpcap"),
        Path("/opt/bin/mergecap"),
        "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        popen=unavailable_popen,
    )

    with pytest.raises(CaptureError, match="dumpcap"):
        capture.start()

    assert capture.state is CaptureState.FAILED


def test_stop_terminates_running_dumpcap_and_marks_capture_stopped(
    tmp_path: Path,
) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    process = _Process()
    capture = CaptureSession(
        Path("/opt/bin/dumpcap"),
        Path("/opt/bin/mergecap"),
        "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        popen=recording_popen(calls, process),
    )
    capture.start()

    capture.stop()

    assert process.terminated is True
    assert process.waited is True
    assert capture.state is CaptureState.STOPPED


def test_stop_marks_capture_failed_when_dumpcap_exits_with_error(
    tmp_path: Path,
) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    capture = CaptureSession(
        Path("/opt/bin/dumpcap"),
        Path("/opt/bin/mergecap"),
        "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        popen=recording_popen(calls, _Process(returncode=1)),
    )
    capture.start()

    with pytest.raises(CaptureError, match="кодом 1"):
        capture.stop()

    assert capture.state is CaptureState.FAILED


def test_collect_closed_segment_registers_only_regular_file(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    assert capture.session is not None
    assert capture._process is not None
    segment = capture.session.path / "segment_00001_20260902000000.pcapng"
    segment.write_bytes(b"pcapng")
    capture._process.stdout = iter([f"{segment}\n"])

    capture.collect_closed_segments()

    assert capture.segments == (segment,)
    assert capture.session.manifest.owned_files == (segment.name,)


def test_limit_stops_capture_and_blocks_continue(tmp_path: Path) -> None:
    capture = started_capture(tmp_path, max_size=1)
    assert capture.session is not None
    assert capture._process is not None
    segment = capture.session.path / "segment_00001_20260902000000.pcapng"
    segment.write_bytes(b"xx")
    capture._process.stdout = iter([f"{segment}\n"])

    capture.collect_closed_segments()

    assert capture.state is CaptureState.LIMIT_REACHED
    with pytest.raises(CaptureError, match="лимит"):
        capture.continue_capture()


def test_collect_closed_segment_rejects_path_outside_session(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    assert capture._process is not None
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"keep")
    capture._process.stdout = iter([f"{outside}\n"])

    with pytest.raises(CaptureError, match="сессии"):
        capture.collect_closed_segments()

    assert outside.read_bytes() == b"keep"
    assert capture.state is CaptureState.FAILED


def test_collect_closed_segment_rejects_path_escaping_session(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    assert capture.session is not None
    assert capture._process is not None
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"keep")
    escaped = capture.session.path / ".." / outside.name
    capture._process.stdout = iter([f"{escaped}\n"])

    with pytest.raises(CaptureError, match="сессии"):
        capture.collect_closed_segments()

    assert outside.read_bytes() == b"keep"
    assert capture.state is CaptureState.FAILED


def test_continue_keeps_confirmed_segment_history(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    assert capture.session is not None
    assert capture._process is not None
    segment = capture.session.path / "segment_00001_20260902000000.pcapng"
    segment.write_bytes(b"pcapng")
    capture._process.stdout = iter([f"{segment}\n"])
    capture.collect_closed_segments()
    capture.stop()

    capture.continue_capture()

    assert capture.state is CaptureState.RUNNING
    assert len(capture.segments) == 1


def test_collect_closed_segments_registers_final_segment_after_stop(
    tmp_path: Path,
) -> None:
    capture = started_capture(tmp_path)
    assert capture.session is not None
    assert capture._process is not None
    segment = capture.session.path / "segment_00001_20260902000000.pcapng"
    segment.write_bytes(b"pcapng")
    capture._process.stdout = iter([f"{segment}\n"])
    capture.stop()

    capture.collect_closed_segments()

    assert capture.segments == (segment,)
    assert capture.session.manifest.owned_files == (segment.name,)


def test_collect_closed_segments_rejects_symbolic_link(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    assert capture.session is not None
    assert capture._process is not None
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"keep")
    link = capture.session.path / "segment-link.pcapng"
    link.symlink_to(outside)
    capture._process.stdout = iter([f"{link}\n"])

    with pytest.raises(CaptureError, match="сессии"):
        capture.collect_closed_segments()

    assert outside.read_bytes() == b"keep"
    assert capture.session.manifest.owned_files == ()


def test_collect_closed_segments_rejects_hard_link(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    assert capture.session is not None
    assert capture._process is not None
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"keep")
    link = capture.session.path / "segment-link.pcapng"
    link.hardlink_to(outside)
    capture._process.stdout = iter([f"{link}\n"])

    with pytest.raises(CaptureError, match="сессии"):
        capture.collect_closed_segments()

    assert outside.read_bytes() == b"keep"
    assert capture.session.manifest.owned_files == ()


def test_collect_closed_segments_rejects_non_regular_object(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    assert capture.session is not None
    assert capture._process is not None
    directory = capture.session.path / "not-a-segment"
    directory.mkdir()
    capture._process.stdout = iter([f"{directory}\n"])

    with pytest.raises(CaptureError, match="сессии"):
        capture.collect_closed_segments()

    assert capture.session.manifest.owned_files == ()


def test_collect_closed_segments_ignores_duplicate(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    assert capture.session is not None
    assert capture._process is not None
    segment = capture.session.path / "segment_00001_20260902000000.pcapng"
    segment.write_bytes(b"pcapng")
    capture._process.stdout = iter([f"{segment}\n", f"{segment}\n"])

    capture.collect_closed_segments()

    assert capture.segments == (segment,)
    assert capture.session.manifest.owned_files == (segment.name,)


def test_collect_closed_segments_does_not_wait_for_open_stdout(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    assert capture._process is not None
    read_fd, write_fd = os.pipe()
    stdout = os.fdopen(read_fd, encoding="utf-8")
    capture._process.stdout = stdout
    completed = threading.Event()

    def collect() -> None:
        capture.collect_closed_segments()
        completed.set()

    thread = threading.Thread(target=collect)
    thread.start()
    try:
        assert completed.wait(timeout=0.1)
    finally:
        os.close(write_fd)
        thread.join()
        stdout.close()


def test_collect_closed_segments_reads_all_available_lines_without_eof(
    tmp_path: Path,
) -> None:
    read_fd, write_fd = os.pipe()
    stdout = os.fdopen(read_fd, encoding="utf-8")
    process = _Process()
    process.stdout = stdout
    capture = started_capture(tmp_path, process=process)
    assert capture.session is not None
    first = capture.session.path / "segment_00001_20260902000000.pcapng"
    second = capture.session.path / "segment_00002_20260902000001.pcapng"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    os.write(write_fd, f"{first}\n{second}\n".encode())

    try:
        deadline = time.monotonic() + 1
        while len(capture.segments) < 2 and time.monotonic() < deadline:
            capture.collect_closed_segments()
            time.sleep(0.01)
    finally:
        os.close(write_fd)
        stdout.close()

    assert capture.segments == (first, second)


def test_save_merges_segments_to_new_destination(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    destination = tmp_path / "saved.pcapng"

    assert capture.save(destination) == destination

    assert destination.read_bytes() == b"merged"
    assert not (tmp_path / "saved.pcapng.part").exists()


def test_save_runs_mergecap_without_shell(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def mergecap(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(((command,), kwargs))
        Path(command[2]).write_bytes(b"merged")
        return completed()

    capture._run = mergecap

    capture.save(tmp_path / "saved.pcapng")

    assert calls[0][1] == {
        "capture_output": True,
        "text": True,
        "check": False,
        "shell": False,
    }


def test_save_does_not_overwrite_existing_file(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    destination = tmp_path / "saved.pcapng"
    destination.write_bytes(b"existing")

    with pytest.raises(CaptureError, match="уже существует"):
        capture.save(destination)

    assert destination.read_bytes() == b"existing"


def test_save_does_not_overwrite_destination_created_while_merging(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "saved.pcapng"

    def mergecap(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        Path(command[2]).write_bytes(b"merged")
        destination.write_bytes(b"existing")
        return completed()

    capture = stopped_capture_with_segment(tmp_path)
    capture._run = mergecap

    with pytest.raises(CaptureError, match="уже существует"):
        capture.save(destination)

    assert destination.read_bytes() == b"existing"
    assert not destination.with_name("saved.pcapng.part").exists()


def test_save_requires_confirmed_segment(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)

    with pytest.raises(CaptureError, match="сегмент"):
        capture.save(tmp_path / "saved.pcapng")


def test_save_resumes_running_capture_only_after_successful_snapshot(
    tmp_path: Path,
) -> None:
    processes = [_Process(), _Process()]

    def mergecap(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        Path(command[2]).write_bytes(b"merged")
        return completed()

    capture = CaptureSession(
        Path("/opt/bin/dumpcap"),
        Path("/opt/bin/mergecap"),
        "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        popen=lambda *_args, **_kwargs: processes.pop(0),
        run=mergecap,
    )
    capture.start()
    assert capture.session is not None
    assert capture._process is not None
    segment = capture.session.path / "segment_00001_20260902000000.pcapng"
    segment.write_bytes(b"pcapng")
    capture._process.stdout = iter([f"{segment}\n"])

    capture.save(tmp_path / "saved.pcapng")

    assert capture.state is CaptureState.RUNNING
    assert capture.segments == (segment,)
    assert len(processes) == 0


def test_restart_creates_new_session_after_confirmed_close(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    old_session = capture.session

    capture.restart()

    assert capture.session != old_session
    assert capture.segments == ()
    assert capture.state is CaptureState.RUNNING


def test_save_removes_part_and_preserves_segments_when_mergecap_fails(
    tmp_path: Path,
) -> None:
    capture = stopped_capture_with_segment(
        tmp_path, merge_result=completed("", "merge error", 1)
    )
    destination = tmp_path / "saved.pcapng"

    with pytest.raises(CaptureError, match="merge error"):
        capture.save(destination)

    assert not destination.exists()
    assert not destination.with_name("saved.pcapng.part").exists()
    assert capture.segments[0].exists()


def test_save_does_not_resume_running_capture_after_mergecap_failure(
    tmp_path: Path,
) -> None:
    process = _Process()
    capture = CaptureSession(
        Path("/opt/bin/dumpcap"),
        Path("/opt/bin/mergecap"),
        "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        popen=recording_popen([], process),
        run=lambda *_args, **_kwargs: completed("", "merge error", 1),
    )
    capture.start()
    assert capture.session is not None
    segment = capture.session.path / "segment_00001_20260902000000.pcapng"
    segment.write_bytes(b"pcapng")
    process.stdout = iter([f"{segment}\n"])

    with pytest.raises(CaptureError, match="merge error"):
        capture.save(tmp_path / "saved.pcapng")

    assert capture.state is CaptureState.STOPPED


def test_close_closes_owned_session_and_marks_capture_closed(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    assert capture.session is not None
    session_path = capture.session.path

    assert capture.close() is True

    assert capture.state is CaptureState.CLOSED
    assert not session_path.exists()


def test_close_does_not_remove_session_when_storage_rejects_it(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    capture.storage.close_session = lambda _: False

    with pytest.raises(CaptureError, match="не удалось"):
        capture.close()


def test_restart_terminates_failed_process_before_closing_session(
    tmp_path: Path,
) -> None:
    processes = [_Process(), _Process()]
    capture = CaptureSession(
        Path("/opt/bin/dumpcap"),
        Path("/opt/bin/mergecap"),
        "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        popen=lambda *_args, **_kwargs: processes.pop(0),
    )
    capture.start()
    assert capture._process is not None
    failed_process = capture._process
    assert capture.session is not None
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"keep")
    failed_process.stdout = iter([f"{outside}\n"])

    with pytest.raises(CaptureError, match="сессии"):
        capture.collect_closed_segments()

    original_close_session = capture.storage.close_session

    def close_session(session: Session) -> bool:
        assert failed_process.terminated is True
        assert failed_process.waited is True
        return original_close_session(session)

    capture.storage.close_session = close_session
    capture.restart()

    assert capture.state is CaptureState.RUNNING


def test_close_terminates_failed_process_before_closing_session(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    assert capture._process is not None
    failed_process = capture._process
    assert capture.session is not None
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"keep")
    failed_process.stdout = iter([f"{outside}\n"])

    with pytest.raises(CaptureError, match="сессии"):
        capture.collect_closed_segments()

    original_close_session = capture.storage.close_session

    def close_session(session: Session) -> bool:
        assert failed_process.terminated is True
        assert failed_process.waited is True
        return original_close_session(session)

    capture.storage.close_session = close_session
    capture.close()

    assert capture.state is CaptureState.CLOSED
