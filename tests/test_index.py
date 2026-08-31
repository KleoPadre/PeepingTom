import sqlite3
from pathlib import Path

import pytest

from wispwire.index import (
    PacketIndex,
    PacketIndexUnavailableError,
    PacketRecord,
)
from wispwire.sqlite_support import SqliteFeatureStatus


def record(global_number: int, *, info: str = "Запрос") -> PacketRecord:
    return PacketRecord(
        global_number=global_number,
        segment_id="segment-1",
        segment_frame_number=global_number,
        captured_at=None,
        relative_time=f"{global_number / 10:.6f}",
        source="192.0.2.1",
        destination="192.0.2.53",
        protocol="DNS",
        length=82,
        info=info,
    )


def test_append_stores_every_packet_field(tmp_path: Path) -> None:
    index = PacketIndex(tmp_path / "packets.sqlite3")

    appended = index.append([record(7, info="Запрос TeLeGrAm")])

    page = index.list_page(limit=10)
    assert appended == 1
    assert len(page.items) == 1
    assert page.items[0].global_number == 7
    assert page.items[0].segment_id == "segment-1"
    assert page.items[0].segment_frame_number == 7
    assert page.items[0].captured_at is None
    assert page.items[0].relative_time == "0.700000"
    assert page.items[0].source == "192.0.2.1"
    assert page.items[0].destination == "192.0.2.53"
    assert page.items[0].protocol == "DNS"
    assert page.items[0].length == 82
    assert page.items[0].info == "Запрос TeLeGrAm"
    assert page.items[0].info_casefold == "запрос telegram"


def test_append_rolls_back_the_whole_batch_on_constraint_error(tmp_path: Path) -> None:
    index = PacketIndex(tmp_path / "packets.sqlite3")

    with pytest.raises(sqlite3.IntegrityError):
        index.append([record(1), record(1)])

    assert index.list_page(limit=10).items == ()


def test_packet_index_does_not_create_file_without_fts5_trigram(tmp_path: Path) -> None:
    index_path = tmp_path / "packets.sqlite3"

    with pytest.raises(PacketIndexUnavailableError, match="trigram недоступен"):
        PacketIndex(
            index_path,
            feature_check=lambda: SqliteFeatureStatus(
                available=False,
                error="SQLite FTS5 trigram недоступен",
            ),
        )

    assert index_path.exists() is False
