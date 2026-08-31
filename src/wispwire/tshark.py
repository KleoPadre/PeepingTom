import csv
import re
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from threading import Thread

from wispwire.packets import PacketDetails, PacketSummary


class TsharkReadError(RuntimeError):
    """Ошибка чтения готового захвата через TShark."""


def build_details_command(
    tshark_path: Path, capture_path: Path, frame_number: int
) -> list[str]:
    return [
        str(tshark_path),
        "-n",
        "-r",
        str(capture_path),
        "-Y",
        f"frame.number == {frame_number}",
        "-V",
        "-x",
    ]


def read_packet_details(
    capture_path: Path,
    tshark_path: Path,
    frame_number: int,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> PacketDetails:
    if frame_number < 1:
        raise TsharkReadError("Номер кадра должен быть не меньше 1.")

    try:
        result = run(
            build_details_command(tshark_path, capture_path, frame_number),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except subprocess.TimeoutExpired as error:
        raise TsharkReadError("Время ожидания ответа TShark истекло.") from error
    except OSError as error:
        raise TsharkReadError(f"Не удалось запустить TShark: {error}") from error

    if result.returncode != 0:
        message = (
            result.stderr.strip() or f"TShark завершился с кодом {result.returncode}."
        )
        raise TsharkReadError(message)

    output = result.stdout.strip()
    if not output:
        raise TsharkReadError("TShark вернул пустой вывод.")

    lines = output.splitlines()
    hex_index = next(
        (
            index
            for index, line in enumerate(lines)
            if re.match(r"^[0-9A-Fa-f]{4}  ", line)
        ),
        None,
    )
    if hex_index is None:
        return PacketDetails(output, "Hex/ASCII-дамп отсутствует.")

    return PacketDetails(
        "\n".join(lines[:hex_index]).strip(),
        "\n".join(lines[hex_index:]).strip(),
    )


def build_fields_command(tshark_path: Path, capture_path: Path) -> list[str]:
    return [
        str(tshark_path),
        "-n",
        "-r",
        str(capture_path),
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


def parse_packet_row(row: str) -> PacketSummary:
    try:
        fields = next(csv.reader([row], delimiter="\t", quotechar='"', strict=True))
    except csv.Error as error:
        raise TsharkReadError("Некорректная строка TSV в выводе TShark.") from error
    if len(fields) != 7:
        raise TsharkReadError("Строка вывода TShark должна содержать ровно семь полей.")

    try:
        number = int(fields[0])
        length = int(fields[5])
    except ValueError as error:
        raise TsharkReadError(
            "Номер или длина пакета в выводе TShark некорректны."
        ) from error

    return PacketSummary(
        number=number,
        relative_time=fields[1],
        source=fields[2],
        destination=fields[3],
        protocol=fields[4],
        length=length,
        info=fields[6],
    )


def iter_packet_summaries(
    capture_path: Path,
    tshark_path: Path,
    limit: int,
    popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
) -> Iterator[PacketSummary]:
    if limit < 1:
        return

    try:
        process = popen(
            build_fields_command(tshark_path, capture_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        raise TsharkReadError(f"Не удалось запустить TShark: {error}") from error

    assert process.stdout is not None
    assert process.stderr is not None

    stderr_stream = process.stderr
    stderr_parts: list[str] = []

    def read_stderr() -> None:
        stderr_parts.append(stderr_stream.read())

    stderr_thread = Thread(target=read_stderr)
    stderr_thread.start()
    completed = False
    stopped_early = False

    try:
        for count, row in enumerate(process.stdout, start=1):
            yield parse_packet_row(row)
            if count >= limit:
                stopped_early = True
                break
        else:
            completed = True
    finally:
        if not completed:
            process.terminate()
        return_code = process.wait()
        stderr_thread.join()

    if not stopped_early and return_code != 0:
        stderr = "".join(stderr_parts)
        message = stderr.strip() or f"TShark завершился с кодом {return_code}."
        raise TsharkReadError(message)
