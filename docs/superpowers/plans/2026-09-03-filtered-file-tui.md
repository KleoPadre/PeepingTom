# План реализации фильтрации файлового TUI

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: используйте `superpowers:subagent-driven-development` (рекомендуется) или `superpowers:executing-plans` для реализации плана по задачам. Шаги отмечаются флажками (`- [ ]`).

**Цель:** добавить в `wispwire open` display filter TShark, независимый поиск по `Info` и TUI-поля фильтрации для готовых PCAP/PCAPNG.

**Архитектура:** файловый режим строит временный индекс исходных сводок и читает отфильтрованные строки через `tshark -Y`, не меняя исходный файл. `FilePacketSource` изолирует запросы к TShark и SQLite, а `WispWireApp` владеет только вводом фильтров, debounce 200 мс, таблицей, деталями и локальными сообщениями ошибок. Первая реализация этапа 7 не подключает live-захват к Textual TUI и не добавляет управление stop/continue/restart/save.

**Технологии:** Python 3.11+, Textual, Typer, TShark, SQLite FTS5 trigram, pytest, pytest-asyncio, Ruff, mypy.

**Спецификация:** `docs/superpowers/specs/2026-08-28-wispwire-tui-design.md`, разделы 6, 7, 8, 10 и 13.

## Общие ограничения

- Код, тесты, документация и пользовательские сообщения — на русском языке; идентификаторы остаются английскими.
- Исходный PCAP/PCAPNG только читается; `tshark` вызывается аргументами-списком, без `shell=True`, `sudo` и сетевых вызовов.
- Display filter передаётся в TShark как есть через `-Y`; приложение не дополняет, не экранирует и не переписывает выражение.
- Поиск `Info` является регистронезависимой подстрокой и использует `PacketIndex.search_info`.
- Display filter и поиск `Info` применяются одновременно; итоговая таблица содержит пересечение результатов по исходному номеру кадра.
- При ошибке display filter таблица сохраняет последний корректный результат и показывает русское сообщение об ошибке.
- Реальные PCAP/PCAPNG и TShark в тестах не запускаются; вызовы подменяются.
- Итоговые проверки: `.venv/bin/python -m pytest`, `.venv/bin/ruff check src tests`, `.venv/bin/ruff format --check src tests`, `.venv/bin/mypy src`, `.venv/bin/wispwire open --help`, `git diff --check`.

---

## Структура файлов

- `src/wispwire/tshark.py` — добавляет опциональный display filter в команду чтения полей.
- `src/wispwire/file_source.py` — создаёт временную файловую сессию, индексирует исходные сводки и отдаёт результаты запросов для TUI.
- `src/wispwire/tui.py` — добавляет поля фильтрации, debounce, перезагрузку таблицы и локальные сообщения статуса.
- `src/wispwire/cli.py` — добавляет `wispwire open PATH --filter TEXT`, создаёт `FilePacketSource` и запускает TUI.
- `tests/test_tshark.py` — проверяет аргументы `-Y` и сохранение потокового чтения.
- `tests/test_file_source.py` — проверяет индексацию, Info search, display filter и пересечение.
- `tests/test_tui.py` — проверяет клавиши `F`, `/`, `Esc`, debounce, ошибки и обновление таблицы.
- `tests/test_cli_commands.py` — проверяет CLI-границу `open --filter`.
- `README.md` — документирует фильтр, поиск и текущие границы файлового TUI.
- `docs/superpowers/plans/2026-08-28-wispwire-tui.md` — отмечает первый пункт этапа 7 только после кода, проверок и коммита.

### Task 1: Display filter в TShark-адаптере

**Файлы:**

- Modify: `src/wispwire/tshark.py`
- Modify: `tests/test_tshark.py`

**Интерфейсы:**

- Consumes: `build_fields_command(tshark_path: Path, capture_path: Path)` и `iter_packet_summaries(capture_path: Path, tshark_path: Path, limit: int, popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen)`.
- Produces: `build_fields_command(tshark_path: Path, capture_path: Path, display_filter: str | None = None) -> list[str]` и `iter_packet_summaries(capture_path: Path, tshark_path: Path, limit: int, display_filter: str | None = None, popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen) -> Iterator[PacketSummary]`.

- [x] **Step 1: написать падающие тесты аргументов display filter.**

```python
def test_build_fields_command_adds_display_filter_without_rewriting() -> None:
    command = build_fields_command(
        Path("/opt/bin/tshark"),
        Path("capture.pcapng"),
        display_filter='udp && dns.qry.name contains "telegram"',
    )

    assert command[:6] == [
        "/opt/bin/tshark",
        "-n",
        "-r",
        "capture.pcapng",
        "-Y",
        'udp && dns.qry.name contains "telegram"',
    ]
    assert command[6:8] == ["-T", "fields"]
```

```python
def test_iter_packet_summaries_passes_display_filter_to_tshark() -> None:
    commands: list[list[str]] = []
    process = FakeProcess(iter(['"1"\t"0.0"\t"a"\t"b"\t"UDP"\t"42"\t"Match"\n']))

    packets = list(
        iter_packet_summaries(
            Path("capture.pcapng"),
            Path("tshark"),
            limit=10,
            display_filter="udp",
            popen=lambda args, **_kwargs: commands.append(args) or process,
        )
    )

    assert packets == [PacketSummary(1, "0.0", "a", "b", "UDP", 42, "Match")]
    assert commands[0][4:6] == ["-Y", "udp"]
```

- [x] **Step 2: подтвердить Red-цикл.**

Run: `.venv/bin/python -m pytest tests/test_tshark.py::test_build_fields_command_adds_display_filter_without_rewriting tests/test_tshark.py::test_iter_packet_summaries_passes_display_filter_to_tshark -v`

Expected: FAIL, потому что `build_fields_command` и `iter_packet_summaries` ещё не принимают `display_filter`.

- [x] **Step 3: реализовать минимальное изменение TShark-команды.**

```python
def build_fields_command(
    tshark_path: Path,
    capture_path: Path,
    display_filter: str | None = None,
) -> list[str]:
    command = [str(tshark_path), "-n", "-r", str(capture_path)]
    if display_filter:
        command.extend(["-Y", display_filter])
    command.extend(
        [
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
    )
    return command
```

`iter_packet_summaries` должен передавать `display_filter` в `build_fields_command`; логика stderr, `limit`, остановки процесса и `TsharkReadError` не меняется.

- [x] **Step 4: проверить Green-цикл TShark.**

Run: `.venv/bin/python -m pytest tests/test_tshark.py -v`

Expected: PASS.

- [x] **Step 5: закоммитить независимую задачу.**

```bash
git add src/wispwire/tshark.py tests/test_tshark.py
git commit -m "Добавить display filter для чтения TShark"
```

### Task 2: файловый источник пакетов с индексом и пересечением фильтров

**Файлы:**

- Create: `src/wispwire/file_source.py`
- Create: `tests/test_file_source.py`

**Интерфейсы:**

- Consumes: `PacketSummary`, `PacketRecord`, `PacketIndex`, `SessionStorage`, `iter_packet_summaries`.
- Produces: `PacketQuery(display_filter: str = "", info_query: str = "", limit: int = 1000)`, `PacketQueryResult(packets: tuple[PacketSummary, ...], error: str | None = None)`, `FilePacketSource(capture_path: Path, tshark_path: Path, storage: SessionStorage | None = None, iter_summaries: Callable[..., Iterator[PacketSummary]] = iter_packet_summaries)`, `FilePacketSource.load(limit: int) -> tuple[PacketSummary, ...]`, `FilePacketSource.query(query: PacketQuery) -> PacketQueryResult` и `FilePacketSource.close() -> None`.

- [x] **Step 1: написать падающий тест начальной индексации.**

```python
def test_file_packet_source_load_indexes_initial_packets(tmp_path: Path) -> None:
    packets = (
        packet(number=1, info="Первый запрос"),
        packet(number=2, info="Ответ telegram"),
    )
    source = FilePacketSource(
        tmp_path / "capture.pcapng",
        Path("tshark"),
        storage=SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=lambda *_args, **_kwargs: iter(packets),
    )

    assert source.load(limit=10) == packets
    assert source.query(PacketQuery(info_query="telegram", limit=10)).packets == (packets[1],)
```

- [x] **Step 2: написать падающий тест display filter и пересечения с Info search.**

```python
def test_file_packet_source_intersects_display_filter_and_info_query(tmp_path: Path) -> None:
    all_packets = (
        packet(number=1, protocol="DNS", info="telegram query"),
        packet(number=2, protocol="TCP", info="telegram tls"),
        packet(number=3, protocol="DNS", info="example query"),
    )
    filtered_packets = (all_packets[0], all_packets[2])
    calls: list[str | None] = []

    def iter_summaries(_capture: Path, _tshark: Path, _limit: int, display_filter=None, **_kwargs):
        calls.append(display_filter)
        return iter(filtered_packets if display_filter == "dns" else all_packets)

    source = FilePacketSource(
        tmp_path / "capture.pcapng",
        Path("tshark"),
        storage=SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=iter_summaries,
    )
    source.load(limit=10)

    result = source.query(PacketQuery(display_filter="dns", info_query="telegram", limit=10))

    assert result == PacketQueryResult((all_packets[0],), None)
    assert calls == [None, "dns"]
```

- [x] **Step 3: написать падающий тест ошибки display filter.**

```python
def test_file_packet_source_returns_filter_error_without_losing_index(tmp_path: Path) -> None:
    packets = (packet(number=1, info="telegram"),)

    def iter_summaries(_capture: Path, _tshark: Path, _limit: int, display_filter=None, **_kwargs):
        if display_filter:
            raise TsharkReadError("Синтаксическая ошибка display filter")
        return iter(packets)

    source = FilePacketSource(
        tmp_path / "capture.pcapng",
        Path("tshark"),
        storage=SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=iter_summaries,
    )
    source.load(limit=10)

    result = source.query(PacketQuery(display_filter="udp &&", limit=10))

    assert result == PacketQueryResult((), "Синтаксическая ошибка display filter")
    assert source.query(PacketQuery(info_query="telegram", limit=10)).packets == packets
```

- [x] **Step 4: подтвердить Red-цикл.**

Run: `.venv/bin/python -m pytest tests/test_file_source.py -v`

Expected: FAIL с `ModuleNotFoundError: No module named 'wispwire.file_source'`.

- [x] **Step 5: реализовать минимальный файловый источник.**

```python
@dataclass(frozen=True)
class PacketQuery:
    display_filter: str = ""
    info_query: str = ""
    limit: int = 1000


@dataclass(frozen=True)
class PacketQueryResult:
    packets: tuple[PacketSummary, ...]
    error: str | None = None
```

```python
class FilePacketSource:
    def __init__(
        self,
        capture_path: Path,
        tshark_path: Path,
        storage: SessionStorage | None = None,
        iter_summaries: Callable[..., Iterator[PacketSummary]] = iter_packet_summaries,
    ) -> None:
        self._capture_path = capture_path
        self._tshark_path = tshark_path
        self._storage = storage or SessionStorage()
        self._iter_summaries = iter_summaries
        self._session = self._storage.create_session()
        self._index = PacketIndex(self._session.path / "packets.sqlite3")
        self._session = self._storage.register_file(
            self._session, self._session.path / "packets.sqlite3"
        )
        self._loaded_packets: dict[int, PacketSummary] = {}

    def load(self, limit: int) -> tuple[PacketSummary, ...]:
        packets = tuple(
            self._iter_summaries(
                self._capture_path,
                self._tshark_path,
                limit,
                display_filter=None,
            )
        )
        self._loaded_packets = {packet.number: packet for packet in packets}
        self._index.append(_records_from_packets(packets))
        return packets
```

`query()` должен валидировать `limit >= 1`, получать `info_numbers` через `PacketIndex.search_info()` при непустом `info_query`, читать display-результат через `iter_packet_summaries(..., display_filter=query.display_filter or None)` при непустом display filter, пересекать множества номеров, сохранять порядок display-результата при активном display filter и порядок индекса при одном Info search. При `TsharkReadError` вернуть `PacketQueryResult((), str(error))`.

Индекс создаёт обычный SQLite-файл внутри session root; сразу после создания его нужно зарегистрировать через `SessionStorage.register_file()` и сохранить возвращённый `Session` в `self._session`, чтобы `close_session()` видел тот же manifest, что записан на диск. `close()` закрывает индекс и вызывает `SessionStorage.close_session(self._session)`. В тестах проверять, что временная сессия удаляется вызовом `source.close()`.

- [x] **Step 6: проверить Green-цикл источника.**

Run: `.venv/bin/python -m pytest tests/test_file_source.py tests/test_index.py tests/test_sessions.py -v`

Expected: PASS.

- [x] **Step 7: закоммитить независимую задачу.**

```bash
git add src/wispwire/file_source.py tests/test_file_source.py
git commit -m "Добавить источник пакетов для файлового TUI"
```

### Task 3: поля фильтрации и поиска в TUI

**Файлы:**

- Modify: `src/wispwire/tui.py`
- Modify: `tests/test_tui.py`

**Интерфейсы:**

- Consumes: `PacketQuery`, `PacketQueryResult` и `query_packets: Callable[[PacketQuery], PacketQueryResult]`.
- Produces: `WispWireApp(packets: tuple[PacketSummary, ...], source_name: str, read_details: Callable[[PacketSummary], PacketDetails], query_packets: Callable[[PacketQuery], PacketQueryResult] | None = None, initial_filter: str = "")`.

- [x] **Step 1: написать падающий тест фокуса display filter.**

```python
@pytest.mark.asyncio
async def test_app_focuses_display_filter_with_f_key() -> None:
    app = WispWireApp((packet(1),), "sample.pcapng", read_details)

    async with app.run_test() as pilot:
        await pilot.press("f")

        assert app.focused.id == "display-filter"
```

- [x] **Step 2: написать падающий тест Info search обновляет таблицу.**

```python
@pytest.mark.asyncio
async def test_app_updates_table_from_info_search() -> None:
    packets = (packet(1, info="telegram"), packet(2, info="example"))
    calls: list[PacketQuery] = []

    def query_packets(query: PacketQuery) -> PacketQueryResult:
        calls.append(query)
        return PacketQueryResult((packets[0],), None)

    app = WispWireApp(packets, "sample.pcapng", read_details, query_packets=query_packets)

    async with app.run_test() as pilot:
        await pilot.press("/")
        await pilot.press("t", "e", "l")
        await pilot.pause(0.25)

        table = app.query_one("#packets", DataTable)
        assert [str(value) for value in table.get_row_at(0)][-1] == "telegram"
        assert calls[-1].info_query == "tel"
```

- [x] **Step 3: написать падающий тест ошибки display filter сохраняет таблицу.**

```python
@pytest.mark.asyncio
async def test_app_keeps_previous_rows_when_display_filter_has_error() -> None:
    packets = (packet(1, info="telegram"),)

    def query_packets(_query: PacketQuery) -> PacketQueryResult:
        return PacketQueryResult((), "Синтаксическая ошибка display filter")

    app = WispWireApp(packets, "sample.pcapng", read_details, query_packets=query_packets)

    async with app.run_test() as pilot:
        await pilot.press("f")
        await pilot.press("u", "d", "p", " ", "&", "&")
        await pilot.pause(0.25)

        table = app.query_one("#packets", DataTable)
        assert str(table.get_row_at(0)[-1]) == "telegram"
        assert "Синтаксическая ошибка display filter" in str(app.query_one("#filter-status", Static).renderable)
```

- [x] **Step 4: написать падающий тест `Esc` очищает активное поле.**

```python
@pytest.mark.asyncio
async def test_app_escape_clears_focused_filter() -> None:
    calls: list[PacketQuery] = []
    app = WispWireApp(
        (packet(1),),
        "sample.pcapng",
        read_details,
        query_packets=lambda query: calls.append(query) or PacketQueryResult((packet(1),), None),
        initial_filter="udp",
    )

    async with app.run_test() as pilot:
        await pilot.press("f")
        await pilot.press("escape")
        await pilot.pause(0.25)

        assert app.query_one("#display-filter", Input).value == ""
        assert calls[-1].display_filter == ""
```

- [x] **Step 5: подтвердить Red-цикл.**

Run: `.venv/bin/python -m pytest tests/test_tui.py -v`

Expected: FAIL, потому что `Input`, `query_packets`, `initial_filter` и `#filter-status` ещё отсутствуют.

- [x] **Step 6: реализовать минимальный TUI-фильтр.**

```python
from textual.widgets import DataTable, Footer, Header, Input, Static
```

`compose()` должен добавить `Input(placeholder="Display filter", id="display-filter")`, `Input(placeholder="Info search", id="info-search")` и `Static(id="filter-status")` над таблицей. `BINDINGS` добавить: `("f", "focus_display_filter", "Фильтр")`, `("/", "focus_info_search", "Info")`, `("escape", "clear_active_filter", "Очистить")`.

```python
def action_focus_display_filter(self) -> None:
    self.query_one("#display-filter", Input).focus()

def action_focus_info_search(self) -> None:
    self.query_one("#info-search", Input).focus()
```

`on_input_changed()` запускает `self.set_timer(0.2, self._apply_filters)`; предыдущий таймер отменяется. `_apply_filters()` строит `PacketQuery(display_filter=display.value, info_query=info.value, limit=len(self._all_packets) or 1)`, вызывает `query_packets`, при `error is None` заменяет `self._packets`, перестраивает таблицу и очищает статус. При ошибке display filter обновляет только `#filter-status` и сохраняет текущую таблицу. Все строки TShark и пользовательского ввода выводятся через `Text`.

- [x] **Step 7: проверить Green-цикл TUI.**

Run: `.venv/bin/python -m pytest tests/test_tui.py -v`

Expected: PASS.

- [x] **Step 8: закоммитить независимую задачу.**

```bash
git add src/wispwire/tui.py tests/test_tui.py
git commit -m "Добавить фильтры в файловый TUI"
```

### Task 4: CLI-граница, документация и статус этапа

**Файлы:**

- Modify: `src/wispwire/cli.py`
- Modify: `tests/test_cli_commands.py`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-08-28-wispwire-tui.md`
- Modify: `docs/superpowers/plans/2026-09-03-filtered-file-tui.md`

**Интерфейсы:**

- Consumes: `FilePacketSource`, `PacketQuery`, `WispWireApp(..., query_packets=..., initial_filter=...)`.
- Produces: `wispwire open PATH [--limit N] [--filter TEXT]` и обновлённый статус первого пункта этапа 7.

- [x] **Step 1: написать падающий CLI-тест `--filter`.**

```python
def test_open_passes_initial_display_filter_to_tui(monkeypatch, tmp_path: Path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    started: list[str] = []

    class FakeSource:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def load(self, _limit: int) -> tuple[PacketSummary, ...]:
            return (packet(),)

        def query(self, _query: PacketQuery) -> PacketQueryResult:
            return PacketQueryResult((packet(),), None)

        def close(self) -> None:
            pass

    class FakeApp:
        def __init__(self, *_args, initial_filter: str = "", **_kwargs) -> None:
            started.append(initial_filter)

        def run(self) -> None:
            pass

    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )
    monkeypatch.setattr("wispwire.cli.FilePacketSource", FakeSource)
    monkeypatch.setattr("wispwire.cli.WispWireApp", FakeApp)

    result = CliRunner().invoke(app, ["open", str(capture_path), "--filter", "udp"])

    assert result.exit_code == 0
    assert started == ["udp"]
```

- [x] **Step 2: написать падающий CLI-тест закрытия временной сессии.**

```python
def test_open_closes_file_packet_source_after_tui_exit(monkeypatch, tmp_path: Path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.touch()
    events: list[str] = []

    class FakeSource:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def load(self, _limit: int) -> tuple[PacketSummary, ...]:
            return (packet(),)

        def query(self, _query: PacketQuery) -> PacketQueryResult:
            return PacketQueryResult((packet(),), None)

        def close(self) -> None:
            events.append("close")

    class FakeApp:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self) -> None:
            events.append("run")

    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda _: ToolStatus("tshark", Path("/opt/bin/tshark"), "4.4.0", None),
    )
    monkeypatch.setattr("wispwire.cli.FilePacketSource", FakeSource)
    monkeypatch.setattr("wispwire.cli.WispWireApp", FakeApp)

    result = CliRunner().invoke(app, ["open", str(capture_path)])

    assert result.exit_code == 0
    assert events == ["run", "close"]
```

- [x] **Step 3: подтвердить Red-цикл.**

Run: `.venv/bin/python -m pytest tests/test_cli_commands.py::test_open_passes_initial_display_filter_to_tui tests/test_cli_commands.py::test_open_closes_file_packet_source_after_tui_exit -v`

Expected: FAIL, потому что CLI ещё не создаёт `FilePacketSource` и не принимает `--filter`.

- [x] **Step 4: реализовать CLI-границу.**

```python
@app.command()
def open(
    capture_path: Path,
    limit: int = typer.Option(1000, min=1, help="Максимальное число выводимых пакетов."),
    display_filter: str = typer.Option("", "--filter", help="Display filter TShark."),
) -> None:
```

После проверки пути и TShark создать `FilePacketSource(capture_path, tshark_path)`, вызвать `source.load(limit)`, передать в `WispWireApp(..., query_packets=source.query, initial_filter=display_filter)`, а `source.close()` вызвать в `finally` после запуска TUI. `TsharkReadError` при начальной загрузке остаётся русской ошибкой с кодом 1, пустой захват не запускает TUI.

- [x] **Step 5: обновить README и статусный план.**

README должен показать:

```bash
.venv/bin/wispwire open ~/Downloads/capture.pcapng --filter "udp"
```

и описать клавиши `F`, `/`, `Esc`, `Tab`, `Q`; отметить, что live-управление через TUI, stop/continue/restart/save и фильтрация закрытых live-сегментов остаются следующим подпланом этапа 7.

В `docs/superpowers/plans/2026-08-28-wispwire-tui.md` отметить первый пункт этапа 7 как `[x]` только после успешных проверок и коммита задачи. Второй пункт этапа 7 оставить `[ ]`.

- [x] **Step 6: выполнить полный набор проверок.**

Run:

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src
.venv/bin/wispwire open --help
git diff --check
```

Expected: все команды завершаются кодом 0.

- [x] **Step 7: проверить дифф и закоммитить.**

Перед коммитом убедиться, что изменения ограничены `src/wispwire/tshark.py`, `src/wispwire/file_source.py`, `src/wispwire/tui.py`, `src/wispwire/cli.py`, тестами, README и планами. Затем выполнить:

```bash
git add src/wispwire/tshark.py src/wispwire/file_source.py src/wispwire/tui.py src/wispwire/cli.py tests/test_tshark.py tests/test_file_source.py tests/test_tui.py tests/test_cli_commands.py README.md docs/superpowers/plans/2026-08-28-wispwire-tui.md docs/superpowers/plans/2026-09-03-filtered-file-tui.md
git commit -m "Завершить фильтрацию файлового TUI"
```

## Покрытие спецификации

| Требование | Задача |
| --- | --- |
| Display filter через `tshark -Y` без переписывания выражения | Task 1, Task 2, Task 4 |
| Ошибка display filter не закрывает TUI и сохраняет последний результат | Task 2, Task 3 |
| Регистронезависимый поиск по `Info` через индекс | Task 2, Task 3 |
| Одновременное применение display filter и Info search | Task 2, Task 3 |
| Поля `F`, `/`, `Esc` и debounce 200 мс | Task 3 |
| Read-only граница `wispwire open` и закрытие временной сессии | Task 4 |
| Документация и статус первого пункта этапа 7 | Task 4 |
