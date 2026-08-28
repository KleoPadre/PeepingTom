import csv
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path

from wispwire.packets import PacketSummary


class TsharkReadError(RuntimeError):
    """Ошибка чтения готового захвата через TShark."""


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
    fields = next(csv.reader([row.replace(r"\"", '""')], delimiter="\t", quotechar='"'))
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

    for count, row in enumerate(process.stdout, start=1):
        yield parse_packet_row(row)
        if count >= limit:
            break

    return_code = process.wait()
    stderr = process.stderr.read()
    if return_code != 0:
        message = stderr.strip() or f"TShark завершился с кодом {return_code}."
        raise TsharkReadError(message)
