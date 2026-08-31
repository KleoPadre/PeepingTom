"""SQLite-индекс сводок пакетов."""

import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from wispwire.sqlite_support import SqliteFeatureStatus, check_fts5_trigram

CREATE_PACKETS_TABLE_SQL = """
CREATE TABLE packets (
    global_number INTEGER NOT NULL UNIQUE,
    segment_id TEXT NOT NULL,
    segment_frame_number INTEGER NOT NULL,
    captured_at TEXT,
    relative_time TEXT NOT NULL,
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    protocol TEXT NOT NULL,
    length INTEGER NOT NULL,
    info TEXT NOT NULL,
    info_casefold TEXT NOT NULL
)
"""
CREATE_FTS_TABLE_SQL = """
CREATE VIRTUAL TABLE packet_info_search USING fts5(
    info_casefold, content='packets', content_rowid='rowid',
    tokenize='trigram case_sensitive 0'
)
"""
CREATE_INSERT_TRIGGER_SQL = """
CREATE TRIGGER packets_after_insert AFTER INSERT ON packets BEGIN
    INSERT INTO packet_info_search(rowid, info_casefold)
    VALUES (new.rowid, new.info_casefold);
END
"""
CREATE_DELETE_TRIGGER_SQL = """
CREATE TRIGGER packets_after_delete AFTER DELETE ON packets BEGIN
    INSERT INTO packet_info_search(packet_info_search, rowid, info_casefold)
    VALUES ('delete', old.rowid, old.info_casefold);
END
"""
CREATE_UPDATE_TRIGGER_SQL = """
CREATE TRIGGER packets_after_update AFTER UPDATE ON packets BEGIN
    INSERT INTO packet_info_search(packet_info_search, rowid, info_casefold)
    VALUES ('delete', old.rowid, old.info_casefold);
    INSERT INTO packet_info_search(rowid, info_casefold)
    VALUES (new.rowid, new.info_casefold);
END
"""
INSERT_PACKET_SQL = """
INSERT INTO packets (global_number, segment_id, segment_frame_number, captured_at,
relative_time, source, destination, protocol, length, info, info_casefold)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""
SELECT_PACKETS_SQL = """
SELECT rowid AS row_id, global_number, segment_id, segment_frame_number,
captured_at, relative_time, source, destination, protocol, length, info,
info_casefold FROM packets ORDER BY global_number ASC, rowid ASC LIMIT ?
"""


@dataclass(frozen=True)
class PacketRecord:
    """Поля пакета до добавления в индекс."""

    global_number: int
    segment_id: str
    segment_frame_number: int
    captured_at: str | None
    relative_time: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str


@dataclass(frozen=True)
class IndexedPacket:
    """Пакет, прочитанный из индекса вместе с внутренним идентификатором."""

    row_id: int
    global_number: int
    segment_id: str
    segment_frame_number: int
    captured_at: str | None
    relative_time: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    info_casefold: str


@dataclass(frozen=True)
class PacketCursor:
    """Позиция последнего пакета в устойчивой выдаче."""

    global_number: int
    row_id: int


@dataclass(frozen=True)
class PacketPage:
    """Страница пакетов и курсор следующей страницы."""

    items: tuple[IndexedPacket, ...]
    next_cursor: PacketCursor | None


class PacketIndexUnavailableError(RuntimeError):
    """SQLite не может создать индекс, необходимый для поиска."""


class PacketIndex:
    """Хранить сводки пакетов в SQLite-файле по переданному пути."""

    def __init__(
        self,
        path: Path,
        feature_check: Callable[[], SqliteFeatureStatus] = check_fts5_trigram,
    ) -> None:
        status = feature_check()
        if not status.available:
            raise PacketIndexUnavailableError(
                status.error or "SQLite FTS5 trigram недоступен"
            )
        self._connection = sqlite3.connect(path)
        self._connection.row_factory = sqlite3.Row
        self._create_schema()

    def append(self, records: Iterable[PacketRecord]) -> int:
        """Добавить пакет сводок одной SQLite-транзакцией."""
        rows = tuple(_record_to_row(record) for record in records)
        with self._connection:
            self._connection.executemany(INSERT_PACKET_SQL, rows)
        return len(rows)

    def list_page(self, limit: int) -> PacketPage:
        """Вернуть начальную страницу пакетов в стабильном порядке."""
        _validate_limit(limit)
        rows = self._connection.execute(SELECT_PACKETS_SQL, (limit,)).fetchall()
        return PacketPage(tuple(_packet_from_row(row) for row in rows), None)

    def close(self) -> None:
        """Закрыть SQLite-соединение с индексом."""
        self._connection.close()

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.execute(CREATE_PACKETS_TABLE_SQL)
            self._connection.execute(CREATE_FTS_TABLE_SQL)
            self._connection.execute(CREATE_INSERT_TRIGGER_SQL)
            self._connection.execute(CREATE_DELETE_TRIGGER_SQL)
            self._connection.execute(CREATE_UPDATE_TRIGGER_SQL)


def _record_to_row(record: PacketRecord) -> tuple[int | str | None, ...]:
    return (
        record.global_number,
        record.segment_id,
        record.segment_frame_number,
        record.captured_at,
        record.relative_time,
        record.source,
        record.destination,
        record.protocol,
        record.length,
        record.info,
        record.info.casefold(),
    )


def _packet_from_row(row: sqlite3.Row) -> IndexedPacket:
    return IndexedPacket(
        row_id=row["row_id"],
        global_number=row["global_number"],
        segment_id=row["segment_id"],
        segment_frame_number=row["segment_frame_number"],
        captured_at=row["captured_at"],
        relative_time=row["relative_time"],
        source=row["source"],
        destination=row["destination"],
        protocol=row["protocol"],
        length=row["length"],
        info=row["info"],
        info_casefold=row["info_casefold"],
    )


def _validate_limit(limit: int) -> None:
    if limit < 1:
        raise ValueError("Размер страницы должен быть положительным")
