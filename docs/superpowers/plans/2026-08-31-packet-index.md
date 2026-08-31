# План реализации индекса пакетов

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: используйте `superpowers:subagent-driven-development` (рекомендуется) или `superpowers:executing-plans` для поэтапной реализации плана. Шаги отмечаются флажками (`- [ ]`).

**Цель:** добавить независимый SQLite-индекс сводок пакетов с устойчивой пагинацией, FTS5-поиском по `Info` и диагностикой поддержки FTS5 trigram.

**Архитектура:** `sqlite_support.py` изолирует проверку возможности SQLite. `index.py` хранит схему, транзакционную пакетную запись, курсоры и поиск, не создавая и не удаляя каталоги сессий. `diagnostics.py` и CLI только отображают структурированный результат проверки; команда `open` не меняется.

**Технологии:** Python 3.11+, стандартная библиотека `sqlite3`, Typer, Rich, pytest, Ruff, mypy.

**Спецификация:** `docs/superpowers/specs/2026-08-31-packet-index-design.md`

## Общие ограничения

- Код, тесты, документация и пользовательские сообщения — на русском языке; идентификаторы остаются английскими.
- Внешние Wireshark CLI и реальные PCAP/PCAPNG не запускаются и не добавляются в Git.
- `wispwire open` сохраняет текущее read-only поведение без индексации и поиска до этапа TUI.
- SQL использует только placeholders; пользовательские `Info` и поисковые строки не конкатенируются с SQL.
- SQLite-файл создаётся только по явно переданному пути; создание каталогов, сегментация, worker и очистка не входят в этап.
- Итоговые проверки: `.venv/bin/python -m pytest`, `.venv/bin/ruff check src tests`, `.venv/bin/ruff format --check src tests`, `.venv/bin/mypy src`.

---

## Структура файлов

- `src/wispwire/sqlite_support.py` — структурированный результат и проверка FTS5 trigram.
- `src/wispwire/index.py` — модели пакета/курсора/страницы, SQLite-схема, запись, выдача страниц и поиск.
- `src/wispwire/diagnostics.py` — добавляет статус FTS5 в `DoctorReport`.
- `src/wispwire/cli.py` — выводит состояние SQLite FTS5 trigram в `doctor`.
- `tests/test_sqlite_support.py` — тесты успешной и неуспешной проверки SQLite.
- `tests/test_index.py` — тесты схемы, пакетной записи, пагинации, поиска и ошибок API.
- `tests/test_diagnostics.py`, `tests/test_cli_commands.py` — тесты интеграции статуса в отчёт и вывод CLI.
- `README.md` — документирует проверку поиска через `doctor`.
- `docs/superpowers/plans/2026-08-28-wispwire-tui.md` — отмечает этап 3 только после всех проверок и коммита.

### Задача 1: проверка SQLite FTS5 trigram

**Файлы:**

- Создать: `src/wispwire/sqlite_support.py`
- Создать: `tests/test_sqlite_support.py`

**Интерфейсы:**

- Производит: `SqliteFeatureStatus(available: bool, error: str | None)` и `check_fts5_trigram(connection_factory: Callable[[], sqlite3.Connection] | None = None) -> SqliteFeatureStatus`.
- Потребители: `collect_doctor_report` и `PacketIndex` из следующих задач.

- [x] **Шаг 1: написать падающие тесты доступной и недоступной FTS5 trigram**

```python
def test_check_fts5_trigram_reports_available() -> None:
    status = check_fts5_trigram()
    assert status == SqliteFeatureStatus(available=True, error=None)


def test_check_fts5_trigram_returns_error_when_virtual_table_cannot_be_created() -> None:
    status = check_fts5_trigram(connection_factory=failing_connection_factory)
    assert status.available is False
    assert "trigram" in (status.error or "")
```

- [x] **Шаг 2: подтвердить падение тестов из-за отсутствующего модуля**

Запустить: `.venv/bin/python -m pytest tests/test_sqlite_support.py -v`  
Ожидается: `ModuleNotFoundError: No module named 'wispwire.sqlite_support'`.

- [x] **Шаг 3: реализовать минимальную проверку**

```python
@dataclass(frozen=True)
class SqliteFeatureStatus:
    available: bool
    error: str | None


def check_fts5_trigram(
    connection_factory: Callable[[], sqlite3.Connection] | None = None,
) -> SqliteFeatureStatus:
    factory = connection_factory or (lambda: sqlite3.connect(":memory:"))
    connection = factory()
    try:
        connection.execute(
            "CREATE VIRTUAL TABLE wispwire_fts_probe "
            "USING fts5(info, tokenize='trigram case_sensitive 0')"
        )
    except sqlite3.Error as error:
        return SqliteFeatureStatus(False, f"SQLite FTS5 trigram недоступен: {error}")
    finally:
        connection.close()
    return SqliteFeatureStatus(True, None)
```

Не скрывать ошибку создания соединения: она должна стать статусом с русским
текстом и исходной причиной. Тестовая фабрика возвращает соединение-обёртку,
у которого `execute` поднимает `sqlite3.OperationalError`.

- [x] **Шаг 4: проверить модуль**

Запустить: `.venv/bin/python -m pytest tests/test_sqlite_support.py -v`  
Ожидается: все тесты проходят.

- [x] **Шаг 5: закоммитить независимую задачу**

```bash
git add src/wispwire/sqlite_support.py tests/test_sqlite_support.py
git commit -m "Добавить проверку SQLite FTS5"
```

### Задача 2: модели и транзакционная запись в индекс

**Файлы:**

- Создать: `src/wispwire/index.py`
- Создать: `tests/test_index.py`

**Интерфейсы:**

- Потребляет: `SqliteFeatureStatus` и `check_fts5_trigram` из `wispwire.sqlite_support`.
- Производит: `PacketRecord`, `IndexedPacket`, `PacketCursor`, `PacketPage`, `PacketIndexUnavailableError` и `PacketIndex`.
- `PacketIndex(path: Path, feature_check: Callable[[], SqliteFeatureStatus] = check_fts5_trigram)` создаёт схему только при доступной возможности.
- `PacketIndex.append(records: Iterable[PacketRecord]) -> int` возвращает число записанных строк.

- [x] **Шаг 1: написать падающие тесты схемы, всех полей и одной транзакции**

```python
def test_append_stores_every_packet_field(tmp_path: Path) -> None:
    index = PacketIndex(tmp_path / "packets.sqlite3")
    index.append([PacketRecord(7, "segment-1", 3, None, "0.250000", "a", "b", "DNS", 82, "Query")])
    page = index.list_page(limit=10)
    assert page.items[0].segment_frame_number == 3
    assert page.items[0].info_casefold == "query"


def test_append_rolls_back_the_whole_batch_on_constraint_error(tmp_path: Path) -> None:
    index = PacketIndex(tmp_path / "packets.sqlite3")
    with pytest.raises(sqlite3.IntegrityError):
        index.append([record(1), record(1)])
    assert index.list_page(limit=10).items == ()
```

Также написать тест, что `PacketIndex` поднимает `PacketIndexUnavailableError`
и не создаёт файл, когда `feature_check` возвращает недоступный статус.

- [x] **Шаг 2: подтвердить ожидаемое падение**

Запустить: `.venv/bin/python -m pytest tests/test_index.py -v`  
Ожидается: ошибка импорта `wispwire.index`.

- [x] **Шаг 3: реализовать модели, схему и пакетную вставку**

```python
@dataclass(frozen=True)
class PacketRecord:
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


class PacketIndex:
    def append(self, records: Iterable[PacketRecord]) -> int:
        rows = [record_to_row(record) for record in records]
        with self._connection:
            self._connection.executemany(INSERT_PACKET_SQL, rows)
        return len(rows)
```

В основной таблице сделать `global_number` уникальным. Добавить `rowid` в
`IndexedPacket`, но не сохранять его в `PacketRecord`. Создать FTS5-таблицу
по `info_casefold` и SQL-триггеры `AFTER INSERT`, `AFTER UPDATE`, `AFTER DELETE`.
Схему создавать после успешной `feature_check`; при недоступности поднять
`PacketIndexUnavailableError(status.error)` до открытия SQLite-файла.

- [x] **Шаг 4: проверить запись**

Запустить: `.venv/bin/python -m pytest tests/test_index.py -v`  
Ожидается: тесты хранения, rollback и недоступной FTS5 проходят.

- [x] **Шаг 5: закоммитить независимую задачу**

```bash
git add src/wispwire/index.py tests/test_index.py
git commit -m "Добавить SQLite-индекс пакетов"
```

### Задача 3: стабильная пагинация и безопасный поиск

**Файлы:**

- Изменить: `src/wispwire/index.py`
- Изменить: `tests/test_index.py`

**Интерфейсы:**

- Потребляет: `PacketIndex`, `PacketRecord` и FTS5-схему из задачи 2.
- Производит: `PacketCursor(global_number: int, row_id: int)`, `PacketPage(items: tuple[IndexedPacket, ...], next_cursor: PacketCursor | None)`, `PacketIndex.list_page(limit: int, after: PacketCursor | None = None) -> PacketPage` и `PacketIndex.search_info(query: str, limit: int, after: PacketCursor | None = None) -> PacketPage`.

- [x] **Шаг 1: написать падающие тесты страниц и поиска**

```python
def test_list_page_does_not_duplicate_or_skip_when_new_packet_is_appended(tmp_path: Path) -> None:
    index = seeded_index(tmp_path, [record(1), record(2), record(3)])
    first = index.list_page(limit=2)
    index.append([record(4)])
    second = index.list_page(limit=2, after=first.next_cursor)
    assert numbers(first, second) == [1, 2, 3, 4]


def test_search_info_finds_casefolded_substring(tmp_path: Path) -> None:
    index = seeded_index(tmp_path, [record(1, info="Запрос TeLeGrAm API")])
    assert [packet.global_number for packet in index.search_info("telegram", 10).items] == [1]
```

Также написать тесты пустого запроса и `limit=0` с `ValueError`, отсутствующих
совпадений, кавычки в поисковом тексте и отдельной курсор-пагинации результатов
поиска.

- [x] **Шаг 2: подтвердить ожидаемое падение**

Запустить: `.venv/bin/python -m pytest tests/test_index.py -v`  
Ожидается: отсутствуют `list_page` и `search_info` либо тесты не проходят.

- [x] **Шаг 3: реализовать выдачу и поиск**

```python
def list_page(self, limit: int, after: PacketCursor | None = None) -> PacketPage:
    self._validate_limit(limit)
    rows = self._connection.execute(PAGE_SQL, self._page_parameters(limit, after)).fetchall()
    return self._page_from_rows(rows, limit)


def search_info(self, query: str, limit: int, after: PacketCursor | None = None) -> PacketPage:
    self._validate_limit(limit)
    if not query:
        raise ValueError("Поисковый запрос не может быть пустым")
    rows = self._connection.execute(SEARCH_SQL, self._search_parameters(query, limit, after)).fetchall()
    return self._page_from_rows(rows, limit)
```

Запрашивать `limit + 1` строку, чтобы определить `next_cursor`; в ответ
возвращать не более `limit`. Во всех запросах сортировать по
`global_number ASC, rowid ASC`; для курсора применять
`(global_number > ?) OR (global_number = ? AND rowid > ?)`. Передавать
поиск через параметр `MATCH`; экранировать двойные кавычки и оборачивать
casefold-строку в FTS5 phrase, чтобы операторы FTS не меняли смысл ввода.

- [x] **Шаг 4: проверить функциональность индекса**

Запустить: `.venv/bin/python -m pytest tests/test_index.py -v`  
Ожидается: все тесты индекса проходят.

- [x] **Шаг 5: закоммитить независимую задачу**

```bash
git add src/wispwire/index.py tests/test_index.py
git commit -m "Добавить поиск и пагинацию пакетов"
```

### Задача 4: диагностика и документация доступности поиска

**Файлы:**

- Изменить: `src/wispwire/diagnostics.py`
- Изменить: `src/wispwire/cli.py`
- Изменить: `tests/test_diagnostics.py`
- Изменить: `tests/test_cli_commands.py`
- Изменить: `README.md`

**Интерфейсы:**

- Потребляет: `SqliteFeatureStatus` и `check_fts5_trigram` из задачи 1.
- Расширяет: `DoctorReport` полем `sqlite_fts5: SqliteFeatureStatus`.
- Расширяет: `collect_doctor_report(..., sqlite_check: Callable[[], SqliteFeatureStatus] = check_fts5_trigram) -> DoctorReport`.

- [x] **Шаг 1: написать падающие тесты отчёта и CLI**

```python
def test_doctor_report_includes_unavailable_fts5_status() -> None:
    report = collect_doctor_report(sqlite_check=lambda: SqliteFeatureStatus(False, "SQLite FTS5 trigram недоступен"))
    assert report.sqlite_fts5.available is False


def test_doctor_prints_fts5_warning(monkeypatch) -> None:
    monkeypatch.setattr("wispwire.cli.collect_doctor_report", unavailable_fts5_report)
    result = CliRunner().invoke(app, ["doctor"])
    assert "SQLite FTS5 trigram" in result.output
```

Дополнить тест успешного отчёта проверкой `SqliteFeatureStatus(True, None)`.

- [x] **Шаг 2: подтвердить ожидаемое падение**

Запустить: `.venv/bin/python -m pytest tests/test_diagnostics.py tests/test_cli_commands.py -v`  
Ожидается: `DoctorReport` не содержит `sqlite_fts5`, а CLI не печатает статус.

- [x] **Шаг 3: реализовать отображение статуса**

```python
console.print(
    "SQLite FTS5 trigram: " + ("OK" if report.sqlite_fts5.available else "ОШИБКА")
)
if not report.sqlite_fts5.available:
    console.print(f"[yellow]Предупреждение: {report.sqlite_fts5.error}[/yellow]")
```

Не добавлять недоступность FTS5 в `capture_warning`: live-захват может
оставаться доступным, а недоступен только индекс/поиск. В README добавить,
что `wispwire doctor` проверяет возможность поиска и как выглядит его ошибка.

- [x] **Шаг 4: проверить диагностику и справку**

Запустить: `.venv/bin/python -m pytest tests/test_diagnostics.py tests/test_cli_commands.py -v`  
Ожидается: все тесты проходят.

- [x] **Шаг 5: закоммитить независимую задачу**

```bash
git add src/wispwire/diagnostics.py src/wispwire/cli.py tests/test_diagnostics.py tests/test_cli_commands.py README.md
git commit -m "Добавить диагностику SQLite FTS5"
```

### Задача 5: итоговая верификация и фиксация статуса

**Файлы:**

- Изменить: `docs/superpowers/plans/2026-08-28-wispwire-tui.md`
- Изменить: `docs/superpowers/plans/2026-08-31-packet-index.md`

**Интерфейсы:**

- Потребляет: завершённые задачи 1–4.
- Производит: подтверждённый статус этапа 3 и сохранённые результаты проверок в истории Git.

- [x] **Шаг 1: выполнить полный набор проверок**

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src
```

Ожидается: каждая команда завершается с кодом 0.

- [x] **Шаг 2: вручную проверить отсутствие изменения команды `open`**

```bash
.venv/bin/wispwire open --help
git diff 652a94f -- src/wispwire/cli.py
```

Ожидается: у `open` нет новых аргументов индексации или поиска; изменения CLI
касаются только вывода `doctor`.

- [x] **Шаг 3: отметить выполненные шаги и этап**

Заменить все флажки задач 1–5 в этом плане на `[x]`. В общем плане поставить
`[x]` у обоих пунктов этапа 3 и дописать хеши фактических коммитов задач.

- [x] **Шаг 4: проверить итоговый diff**

```bash
git diff --check HEAD~1..HEAD
git status --short --branch
```

Ожидается: нет ошибок whitespace; после коммита рабочее дерево чистое.

- [x] **Шаг 5: закоммитить статус этапа**

```bash
git add docs/superpowers/plans/2026-08-28-wispwire-tui.md docs/superpowers/plans/2026-08-31-packet-index.md
git commit -m "Отметить выполнение этапа индекса"
```

## Покрытие спецификации

- Временный SQLite-файл, модель полей и транзакционная пакетная запись — задача 2.
- Устойчивая cursor-пагинация — задача 3.
- FTS5 trigram, casefold-поиск, отсутствие поддержки и безопасная передача текста — задачи 1–3.
- Структурированный результат `doctor` и пользовательская диагностика — задача 4.
- Полный набор проверок, сохранение статуса и отсутствие изменения `open` — задача 5.
