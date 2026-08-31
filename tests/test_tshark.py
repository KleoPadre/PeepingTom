import subprocess
from collections.abc import Iterator
from pathlib import Path
from threading import Event

import pytest

from wispwire.packets import PacketDetails, PacketSummary
from wispwire.tshark import (
    TsharkReadError,
    build_details_command,
    build_fields_command,
    iter_packet_summaries,
    parse_packet_row,
    read_packet_details,
)


def completed(
    stdout: str, stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_build_details_command_reads_only_selected_frame() -> None:
    assert build_details_command(
        Path("/opt/bin/tshark"), Path("capture.pcapng"), 7
    ) == [
        "/opt/bin/tshark",
        "-n",
        "-r",
        "capture.pcapng",
        "-Y",
        "frame.number == 7",
        "-V",
        "-x",
    ]


def test_read_packet_details_separates_tree_and_hex() -> None:
    result = completed("Frame 7: 72 bytes\n\n0000  01 02 03 04   ....\n")

    assert read_packet_details(
        Path("capture.pcapng"), Path("tshark"), 7, run=lambda *_a, **_k: result
    ) == PacketDetails("Frame 7: 72 bytes", "0000  01 02 03 04   ....")


def test_read_packet_details_rejects_non_positive_frame_without_running_tshark() -> (
    None
):
    def unexpected_run(
        *_args: object, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        raise AssertionError("TShark не должен запускаться")

    with pytest.raises(TsharkReadError, match="не меньше 1"):
        read_packet_details(
            Path("capture.pcapng"), Path("tshark"), 0, run=unexpected_run
        )


def test_read_packet_details_reports_tshark_startup_error() -> None:
    def failing_run(
        *_args: object, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        raise OSError("Нет такого файла")

    with pytest.raises(TsharkReadError, match="Не удалось запустить"):
        read_packet_details(Path("capture.pcapng"), Path("tshark"), 7, run=failing_run)


def test_read_packet_details_reports_timeout_in_russian() -> None:
    def timing_out_run(
        *_args: object, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(["tshark"], timeout=5)

    with pytest.raises(TsharkReadError, match="Время ожидания"):
        read_packet_details(
            Path("capture.pcapng"), Path("tshark"), 7, run=timing_out_run
        )


def test_read_packet_details_reports_stderr_for_nonzero_exit() -> None:
    result = completed("", stderr="Файл повреждён\n", returncode=2)

    with pytest.raises(TsharkReadError, match="Файл повреждён"):
        read_packet_details(
            Path("capture.pcapng"), Path("tshark"), 7, run=lambda *_a, **_k: result
        )


def test_read_packet_details_reports_empty_stdout() -> None:
    with pytest.raises(TsharkReadError, match="пустой вывод"):
        read_packet_details(
            Path("capture.pcapng"),
            Path("tshark"),
            7,
            run=lambda *_a, **_k: completed("\n"),
        )


def test_read_packet_details_reports_missing_hex_dump() -> None:
    result = completed("Frame 7: 72 bytes\n\nEthernet II\n")

    assert read_packet_details(
        Path("capture.pcapng"), Path("tshark"), 7, run=lambda *_a, **_k: result
    ) == PacketDetails(
        "Frame 7: 72 bytes\n\nEthernet II", "Hex/ASCII-дамп отсутствует."
    )


def test_read_packet_details_uses_safe_tshark_run_options() -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def recording_run(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return completed("Frame 7: 72 bytes\n")

    read_packet_details(Path("capture.pcapng"), Path("tshark"), 7, run=recording_run)

    assert calls == [
        (
            (
                [
                    "tshark",
                    "-n",
                    "-r",
                    "capture.pcapng",
                    "-Y",
                    "frame.number == 7",
                    "-V",
                    "-x",
                ],
            ),
            {"capture_output": True, "text": True, "check": False, "timeout": 5},
        )
    ]


class FakeProcess:
    def __init__(
        self,
        stdout: Iterator[str],
        stderr: str = "",
        returncode: int = 0,
    ) -> None:
        self.stdout = stdout
        self.stderr = FakeStderr(stderr)
        self.returncode = returncode
        self.wait_called = False
        self.terminate_called = False

    def wait(self) -> int:
        self.wait_called = True
        return self.returncode

    def terminate(self) -> None:
        self.terminate_called = True
        self.returncode = -15


class FakeStderr:
    def __init__(self, value: str) -> None:
        self.value = value
        self.read_started = Event()

    def read(self) -> str:
        self.read_started.set()
        return self.value


class LimitProcess(FakeProcess):
    def wait(self) -> int:
        if not self.terminate_called:
            raise AssertionError("Процесс должен быть остановлен до ожидания")
        return super().wait()


class StderrFirstProcess(FakeProcess):
    def wait(self) -> int:
        if not self.stderr.read_started.wait(timeout=0.1):
            raise AssertionError("stderr должен читаться до ожидания процесса")
        return super().wait()


def test_build_fields_command_uses_read_only_tshark_fields() -> None:
    command = build_fields_command(Path("/opt/bin/tshark"), Path("capture.pcapng"))

    assert command == [
        "/opt/bin/tshark",
        "-n",
        "-r",
        "capture.pcapng",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "escape=y",
        "-E",
        "occurrence=f",
        "-e",
        "frame.number",
        "-e",
        "frame.time_relative",
        "-e",
        "_ws.col.Source",
        "-e",
        "_ws.col.Destination",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "frame.len",
        "-e",
        "_ws.col.Info",
    ]


def test_parse_packet_row_preserves_tshark_doubled_quotes_and_trailing_backslash() -> (
    None
):
    row = (
        '"7"\t"0.250000"\t"10.0.0.1"\t"10.0.0.2"\t"DNS"\t"82"'
        '\t"Query ""example""\\\\"\n'
    )

    packet = parse_packet_row(row)

    assert packet.info == 'Query "example"\\\\'


def test_parse_packet_row_reports_malformed_tsv() -> None:
    row = '"7"\t"0.250000"\t"10.0.0.1"\t"10.0.0.2"\t"DNS"\t"82"\t"Query\n'

    with pytest.raises(TsharkReadError, match="Некорректн"):
        parse_packet_row(row)


def test_iter_packet_summaries_stops_after_limit() -> None:
    process = LimitProcess(
        iter(
            [
                '"1"\t"0.000000"\t"a"\t"b"\t"DNS"\t"72"\t"Первый"\n',
                '"2"\t"0.100000"\t"c"\t"d"\t"TCP"\t"64"\t"Второй"\n',
            ]
        )
    )

    packets = list(
        iter_packet_summaries(
            Path("capture.pcapng"),
            Path("tshark"),
            limit=1,
            popen=lambda *_args, **_kwargs: process,
        )
    )

    assert packets == [PacketSummary(1, "0.000000", "a", "b", "DNS", 72, "Первый")]
    assert process.terminate_called
    assert process.wait_called


def test_iter_packet_summaries_drains_stderr_before_waiting_for_process() -> None:
    process = StderrFirstProcess(iter(()), stderr="Предупреждение\n")

    packets = list(
        iter_packet_summaries(
            Path("capture.pcapng"),
            Path("tshark"),
            limit=1,
            popen=lambda *_args, **_kwargs: process,
        )
    )

    assert packets == []
    assert process.wait_called


def test_iter_packet_summaries_does_not_start_process_for_non_positive_limit() -> None:
    def unexpected_popen(*_args: object, **_kwargs: object) -> FakeProcess:
        raise AssertionError("Процесс не должен запускаться")

    packets = list(
        iter_packet_summaries(
            Path("capture.pcapng"), Path("tshark"), limit=0, popen=unexpected_popen
        )
    )

    assert packets == []


def test_iter_packet_summaries_reports_tshark_stderr_without_traceback() -> None:
    process = FakeProcess(iter(()), stderr="Файл повреждён\n", returncode=2)

    with pytest.raises(TsharkReadError, match="Файл повреждён") as error:
        list(
            iter_packet_summaries(
                Path("capture.pcapng"),
                Path("tshark"),
                limit=1,
                popen=lambda *_args, **_kwargs: process,
            )
        )

    assert "Traceback" not in str(error.value)


def test_iter_packet_summaries_reports_malformed_row_after_previous_packets() -> None:
    process = FakeProcess(
        iter(
            [
                '"1"\t"0.000000"\t"a"\t"b"\t"DNS"\t"72"\t"Первый"\n',
                '"2"\t"0.100000"\t"c"\t"d"\t"TCP"\t"64"\n',
            ]
        )
    )
    packets = iter_packet_summaries(
        Path("capture.pcapng"),
        Path("tshark"),
        limit=2,
        popen=lambda *_args, **_kwargs: process,
    )

    assert next(packets).number == 1
    with pytest.raises(TsharkReadError, match="семь"):
        next(packets)

    assert process.terminate_called
    assert process.wait_called


def test_iter_packet_summaries_reports_startup_error() -> None:
    def failing_popen(*_args: object, **_kwargs: object) -> FakeProcess:
        raise OSError("Нет такого файла")

    with pytest.raises(TsharkReadError, match="Не удалось запустить"):
        list(
            iter_packet_summaries(
                Path("capture.pcapng"), Path("tshark"), limit=1, popen=failing_popen
            )
        )
