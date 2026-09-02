from __future__ import annotations

import subprocess
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
from wispwire.sessions import SessionStorage


class _Process:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.terminated = False
        self.waited = False

    def terminate(self) -> None:
        self.terminated = True

    def wait(self) -> int:
        self.waited = True
        return self.returncode


def started_capture(tmp_path: Path, *, max_size: int = 1_073_741_824) -> CaptureSession:
    capture = CaptureSession(
        Path("/opt/bin/dumpcap"),
        Path("/opt/bin/mergecap"),
        "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        max_size=max_size,
        popen=recording_popen([]),
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
