from collections.abc import Iterator
from pathlib import Path
from threading import Event

import pytest

from wispwire.packets import PacketSummary
from wispwire.tshark import (
    TsharkReadError,
    build_fields_command,
    iter_packet_summaries,
    parse_packet_row,
)


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
