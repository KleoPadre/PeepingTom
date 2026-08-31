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


def test_list_page_does_not_duplicate_or_skip_when_new_packet_is_appended(
    tmp_path: Path,
) -> None:
    index = PacketIndex(tmp_path / "packets.sqlite3")
    index.append([record(1), record(2), record(3)])

    first_page = index.list_page(limit=2)
    index.append([record(4)])
    second_page = index.list_page(limit=2, after=first_page.next_cursor)

    assert [packet.global_number for packet in first_page.items] == [1, 2]
    assert [packet.global_number for packet in second_page.items] == [3, 4]


def test_search_info_finds_casefolded_substring(tmp_path: Path) -> None:
    index = PacketIndex(tmp_path / "packets.sqlite3")
    index.append([record(1, info="Запрос TeLeGrAm API"), record(2, info="DNS")])

    page = index.search_info("telegram", limit=10)

    assert [packet.global_number for packet in page.items] == [1]


def test_search_info_treats_quotation_mark_as_literal_text(tmp_path: Path) -> None:
    index = PacketIndex(tmp_path / "packets.sqlite3")
    index.append([record(1, info='Поле "значение"'), record(2, info="Другое")])

    page = index.search_info('"значение"', limit=10)

    assert [packet.global_number for packet in page.items] == [1]


def test_search_info_paginates_matches_with_cursor(tmp_path: Path) -> None:
    index = PacketIndex(tmp_path / "packets.sqlite3")
    index.append(
        [
            record(1, info="telegram one"),
            record(2, info="telegram two"),
            record(3, info="telegram three"),
        ]
    )

    first_page = index.search_info("telegram", limit=2)
    second_page = index.search_info("telegram", limit=2, after=first_page.next_cursor)

    assert [packet.global_number for packet in first_page.items] == [1, 2]
    assert [packet.global_number for packet in second_page.items] == [3]
    assert second_page.next_cursor is None


@pytest.mark.parametrize("limit", [0, -1])
def test_list_page_rejects_non_positive_limit(tmp_path: Path, limit: int) -> None:
    index = PacketIndex(tmp_path / "packets.sqlite3")

    with pytest.raises(ValueError, match="Размер страницы"):
        index.list_page(limit=limit)


def test_search_info_rejects_empty_query(tmp_path: Path) -> None:
    index = PacketIndex(tmp_path / "packets.sqlite3")

    with pytest.raises(ValueError, match="Поисковый запрос"):
        index.search_info("", limit=10)
