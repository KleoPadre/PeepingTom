"""Проверки возможностей SQLite, требуемых для индекса пакетов."""

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class SqliteFeatureStatus:
    """Результат проверки отдельной возможности SQLite."""

    available: bool
    error: str | None


def check_fts5_trigram(
    connection_factory: Callable[[], sqlite3.Connection] | None = None,
) -> SqliteFeatureStatus:
    """Проверить поддержку FTS5 с регистронезависимым trigram-токенизатором."""
    factory = connection_factory or _open_memory_connection
    connection: sqlite3.Connection | None = None
    try:
        connection = factory()
        connection.execute(
            "CREATE VIRTUAL TABLE wispwire_fts_probe "
            "USING fts5(info, tokenize='trigram case_sensitive 0')"
        )
    except sqlite3.Error as error:
        return SqliteFeatureStatus(False, f"SQLite FTS5 trigram недоступен: {error}")
    finally:
        if connection is not None:
            connection.close()

    return SqliteFeatureStatus(True, None)


def _open_memory_connection() -> sqlite3.Connection:
    """Открыть отдельную краткоживущую SQLite-базу для проверки возможности."""
    return sqlite3.connect(":memory:")
