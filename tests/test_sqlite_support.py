import sqlite3

from wispwire.sqlite_support import SqliteFeatureStatus, check_fts5_trigram


class FailingConnection:
    def execute(self, _statement: str) -> None:
        raise sqlite3.OperationalError("токенизатор trigram не найден")

    def close(self) -> None:
        pass


def test_check_fts5_trigram_reports_available() -> None:
    status = check_fts5_trigram()

    assert status == SqliteFeatureStatus(available=True, error=None)


def test_check_fts5_trigram_returns_error_when_virtual_table_cannot_be_created() -> (
    None
):
    status = check_fts5_trigram(connection_factory=FailingConnection)

    assert status.available is False
    assert status.error == (
        "SQLite FTS5 trigram недоступен: токенизатор trigram не найден"
    )
