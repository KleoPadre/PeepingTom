# PacketScope TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Создать PacketScope — реактивное TUI-приложение для live-захвата и просмотра PCAP/PCAPNG со стандартными display filters TShark, поиском по `Info`, деталями пакета и безопасным временным хранением.

**Architecture:** Python-приложение запускает внешние CLI-инструменты Wireshark без `shell=True`, пишет live-захват в сегменты PCAPNG и индексирует метаданные в SQLite FTS5. Textual получает события пакетами, показывает виртуализированную таблицу и загружает дерево/hex выбранного кадра по запросу.

**Tech Stack:** Python 3.11+, Textual, Typer, SQLite FTS5, TShark/Dumpcap/Mergecap, pytest, pytest-asyncio, Ruff, mypy, Homebrew.

**Spec:** `docs/superpowers/specs/2026-08-28-packetscope-tui-design.md`

## Global Constraints

- Поддерживаемые платформы первой версии: macOS Apple Silicon, Linux ARM64 и Linux x86_64.
- macOS Intel и Windows не реализуются в этом плане.
- Минимальная версия Python — 3.11.
- Runtime-зависимости разрешены только под MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, PSF-2.0 или ISC; Wireshark используется только как внешний GPL-2.0-or-later процесс.
- Все subprocess запускаются списком аргументов, с `shell=False` и без интерполяции пользовательского ввода.
- Display filter передаётся в `tshark -Y` без изменения; Info search — регистронезависимая подстрока без собственного языка запросов.
- UI применяет packet batch каждые 50–100 мс; display-filter debounce — 200 мс; PCAPNG-сегмент закрывается каждые 500 мс.
- Общий размер временной сессии, включая PCAPNG и SQLite, не превышает 1 ГБ по умолчанию.
- Документация, комментарии, CLI/TUI-тексты и сообщения коммитов пишутся по-русски.

---

## Карта файлов

```text
pyproject.toml                         сборка, зависимости, инструменты и CLI entry point
src/packetscope/__init__.py           версия пакета
src/packetscope/__main__.py           запуск через python -m packetscope
src/packetscope/cli.py                команды doctor/interfaces/capture/open
src/packetscope/config.py             лимиты, интервалы и каталоги платформ
src/packetscope/models.py             PacketSummary, Segment, ToolPaths и состояния
src/packetscope/errors.py             типизированные ошибки приложения
src/packetscope/services/tools.py     поиск и диагностика CLI Wireshark
src/packetscope/services/tshark.py    аргументы, live-парсер, анализ файлов и details
src/packetscope/services/index.py     SQLite schema, FTS5, запись и запрос страниц
src/packetscope/services/session.py   manifest, сегменты и безопасный cleanup
src/packetscope/services/filtering.py display-filter generations и Info search
src/packetscope/services/capture.py   конечный автомат live-сессии
src/packetscope/services/save.py      snapshot и mergecap
src/packetscope/services/details.py   дерево протоколов и hex выбранного кадра
src/packetscope/tui/app.py            корневое Textual-приложение
src/packetscope/tui/messages.py       сообщения между workers и UI
src/packetscope/tui/screens/start.py  выбор режима и интерфейса
src/packetscope/tui/screens/packets.py основной экран варианта C
src/packetscope/tui/widgets/filters.py два реактивных поля
src/packetscope/tui/widgets/table.py   виртуализированная таблица
src/packetscope/tui/widgets/details.py дерево и hex/ASCII
src/packetscope/tui/widgets/actions.py контекстная нижняя панель
src/packetscope/tui/packetscope.tcss  адаптивная раскладка и цвета протоколов
tests/unit/                           изолированные тесты сервисов и виджетов
tests/integration/                    тесты с реальными CLI Wireshark
tests/fixtures/                       минимальные обезличенные входные данные
tests/factories.py                    фабрики PacketSummary и тестовых сессий
tests/conftest.py                     общие pytest fixtures
packaging/homebrew/                   проверяемые исходники formula/cask
```

### Task 1: Основа Python-пакета и CLI

**Files:**
- Create: `pyproject.toml`
- Create: `src/packetscope/__init__.py`
- Create: `src/packetscope/__main__.py`
- Create: `src/packetscope/cli.py`
- Create: `src/packetscope/config.py`
- Create: `src/packetscope/errors.py`
- Test: `tests/unit/test_cli.py`

**Interfaces:**
- Produces: `packetscope.cli.app: typer.Typer`
- Produces: `packetscope.config.AppConfig.default() -> AppConfig`
- Produces: исключения `PacketScopeError`, `DependencyError`, `CaptureError`, `FilterError`, `StorageError`

- [ ] **Step 1: Write the failing CLI test**

```python
from typer.testing import CliRunner
from packetscope.cli import app

runner = CliRunner()

def test_version_returns_package_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "PacketScope 0.1.0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_cli.py -v`  
Expected: FAIL with `ModuleNotFoundError: No module named 'packetscope'`.

- [ ] **Step 3: Create package metadata and minimal CLI**

Set `requires-python = ">=3.11"`, runtime dependencies `textual>=8,<9` and `typer>=0.16,<1`, entry point `packetscope = "packetscope.cli:app"`, and development groups for pytest, pytest-asyncio, Ruff and mypy. Implement:

```python
__version__ = "0.1.0"

app = typer.Typer(help="Захват и анализ сетевых пакетов в терминале.")

@app.callback(invoke_without_command=True)
def main(version: bool = typer.Option(False, "--version")) -> None:
    if version:
        typer.echo(f"PacketScope {__version__}")
        raise typer.Exit()
```

- [ ] **Step 4: Add immutable configuration defaults**

Implement `AppConfig` as frozen dataclass with `segment_duration_ms=500`, `ui_batch_ms=75`, `filter_debounce_ms=200`, `max_session_bytes=1_000_000_000` and platform-specific cache roots from the approved spec.

- [ ] **Step 5: Run package checks**

Run: `python -m pytest tests/unit/test_cli.py -v && ruff check src tests && mypy src`  
Expected: PASS; Ruff and mypy report no errors.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/packetscope tests/unit/test_cli.py
git commit -m "Создать основу Python-пакета и CLI"
```

### Task 2: Модели пакетов и адаптер TShark

**Files:**
- Create: `src/packetscope/models.py`
- Create: `src/packetscope/services/tools.py`
- Create: `src/packetscope/services/tshark.py`
- Create: `tests/factories.py`
- Create: `tests/conftest.py`
- Test: `tests/unit/services/test_tools.py`
- Test: `tests/unit/services/test_tshark.py`

**Interfaces:**
- Produces: `PacketSummary(global_number: int, segment_id: str | None, segment_frame_number: int | None, captured_at: datetime, relative_time: float, source: str, destination: str, protocol: str, length: int, info: str)`; live-строка остаётся provisional до закрытия сегмента
- Produces: `ToolPaths.discover() -> ToolPaths`
- Produces: `TsharkAdapter.live_args(interface: str, output_pattern: Path, capture_filter: str | None) -> list[str]`
- Produces: `TsharkAdapter.parse_fields_line(line: str, segment_id: str | None, global_number: int) -> PacketSummary`
- Produces: `async TsharkAdapter.validate_display_filter(expression: str) -> None`

- [ ] **Step 1: Write failing parser and argument tests**

```python
def test_parse_fields_preserves_info_spaces() -> None:
    line = "7\t1787911200.125000\t0.125000\t192.168.1.4\t91.108.9.6\tSTUN\t128\tAllocate Error Response realm: telegram.org"
    packet = adapter.parse_fields_line(line, segment_id="s1", global_number=9)
    assert packet.segment_frame_number == 7
    assert packet.protocol == "STUN"
    assert packet.info.endswith("telegram.org")

def test_live_args_do_not_use_shell_string() -> None:
    args = adapter.live_args(interface="en0", output_pattern="capture.pcapng")
    assert args[0].endswith("tshark")
    assert "-P" in args and "-l" in args and "-T" in args
    assert "_ws.col.Info" in args
```

- [ ] **Step 2: Run tests to verify failure**

Run: `python -m pytest tests/unit/services/test_tools.py tests/unit/services/test_tshark.py -v`  
Expected: FAIL because `ToolPaths` and `TsharkAdapter` do not exist.

- [ ] **Step 3: Implement discovery and version checks**

Use `shutil.which` for `tshark`, `dumpcap`, `mergecap`; run each with `--version`; return absolute paths. Raise `DependencyError` listing exact missing commands.

- [ ] **Step 4: Add shared test factories**

Implement `tests.factories.packet(number: int = 1, info: str = "") -> PacketSummary` with fixed UTC timestamp, addresses and protocol, plus pytest fixtures `tool_paths`, `adapter` and `tmp_session_root` in `tests/conftest.py`.

- [ ] **Step 5: Implement live arguments and escaped TSV parser**

Use `-P -l -T fields`, explicit `-e frame.number`, `frame.time_epoch`, `frame.time_relative`, `_ws.col.Source`, `_ws.col.Destination`, `_ws.col.Protocol`, `frame.len`, `_ws.col.Info`, and `-E escape=y -E occurrence=f`. Split on tab into exactly eight fields and decode TShark C-style escapes without evaluating Python literals.

- [ ] **Step 6: Implement filter validation**

Run TShark against an empty valid PCAPNG fixture with `-Y expression -T fields -e frame.number`. Exit code 0 is valid; nonzero stderr becomes `FilterError`, содержащей очищенный stderr процесса.

- [ ] **Step 7: Run tests and static checks**

Run: `python -m pytest tests/unit/services/test_tools.py tests/unit/services/test_tshark.py -v && ruff check src tests && mypy src`  
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/packetscope/models.py src/packetscope/services tests/unit/services
git commit -m "Добавить адаптер TShark и модели пакетов"
```

### Task 3: Временная сессия и безопасная очистка

**Files:**
- Create: `src/packetscope/services/session.py`
- Test: `tests/unit/services/test_session.py`

**Interfaces:**
- Produces: `SessionManifest(session_id: UUID, pid: int, created_at: datetime, schema_version: int, files: tuple[str, ...])`
- Produces: `SessionStore.create(config: AppConfig) -> SessionStore`
- Produces: `SessionStore.register_file(path: Path) -> None`
- Produces: `SessionStore.total_bytes() -> int`
- Produces: `SessionStore.cleanup() -> None`
- Produces: `cleanup_orphaned_sessions(root: Path, live_pids: set[int]) -> list[Path]`

- [ ] **Step 1: Write failing path-safety tests**

```python
def test_cleanup_removes_owned_orphan(tmp_path: Path) -> None:
    store = SessionStore.create_for_test(tmp_path, pid=999999)
    segment = store.root / "capture_00001.pcapng"
    segment.write_bytes(b"pcap")
    store.register_file(segment)
    removed = cleanup_orphaned_sessions(tmp_path, live_pids=set())
    assert removed == [store.root]
    assert not store.root.exists()

def test_cleanup_rejects_manifest_path_escape(tmp_path: Path) -> None:
    outside = tmp_path / "keep.txt"
    outside.write_text("важно")
    store = SessionStore.create_for_test(tmp_path / "sessions", pid=999999)
    store.write_manifest_files(["../../keep.txt"])
    cleanup_orphaned_sessions(tmp_path / "sessions", live_pids=set())
    assert outside.read_text() == "важно"
```

- [ ] **Step 2: Run tests to verify failure**

Run: `python -m pytest tests/unit/services/test_session.py -v`  
Expected: FAIL because `SessionStore` is undefined.

- [ ] **Step 3: Implement manifest and ownership validation**

Write manifest atomically through `manifest.json.part`; resolve every registered path and require `path.is_relative_to(session_root.resolve())`; reject symlinks before deletion.

- [ ] **Step 4: Implement byte accounting and lifecycle cleanup**

Sum regular files with `stat().st_size`. Cleanup current session on normal close; orphan cleanup accepts only UUID-named directories, schema version 1, dead PID and valid owned paths.

- [ ] **Step 5: Test interruption hooks**

Add tests that `SIGINT`, `SIGTERM` and `SIGHUP` callbacks request capture shutdown before calling cleanup; simulate callbacks without sending signals to pytest itself.

- [ ] **Step 6: Verify and commit**

Run: `python -m pytest tests/unit/services/test_session.py -v && ruff check src tests && mypy src`  
Expected: PASS.

```bash
git add src/packetscope/services/session.py tests/unit/services/test_session.py
git commit -m "Добавить безопасное хранение временных сессий"
```

### Task 4: SQLite-индекс и поиск по Info

**Files:**
- Create: `src/packetscope/services/index.py`
- Test: `tests/unit/services/test_index.py`

**Interfaces:**
- Produces: `PacketIndex.open(path: Path) -> PacketIndex`
- Produces: `PageRequest(offset: int, limit: int)` and `PacketPage(rows: tuple[PacketSummary, ...], total: int, offset: int, limit: int)`
- Produces: `PacketIndex.insert_batch(packets: Sequence[PacketSummary]) -> None`
- Produces: `PacketIndex.search_info(query: str, page: PageRequest) -> PacketPage`
- Produces: `PacketIndex.query(display_generation: int | None, info_query: str, page: PageRequest) -> PacketPage`
- Produces: `PacketIndex.replace_display_matches(generation: int, packet_ids: Iterable[int]) -> None`

- [ ] **Step 1: Write failing FTS and pagination tests**

```python
def test_info_search_matches_substring_case_insensitively(index: PacketIndex) -> None:
    index.insert_batch([packet(info="Allocate Error Response realm: telegram.org")])
    assert index.search_info("TELEGRAM", PageRequest(offset=0, limit=50)).total == 1

def test_display_and_info_filters_intersect(index: PacketIndex) -> None:
    packets = [packet(number=1, info="telegram"), packet(number=2, info="telegram")]
    index.insert_batch(packets)
    index.replace_display_matches(3, [2])
    page = index.query(3, "telegram", PageRequest(0, 50))
    assert [row.global_number for row in page.rows] == [2]
```

- [ ] **Step 2: Run tests to verify failure**

Run: `python -m pytest tests/unit/services/test_index.py -v`  
Expected: FAIL because `PacketIndex` is undefined.

- [ ] **Step 3: Implement schema and FTS5 trigram capability check**

Create `segments`, `packets`, `display_matches` and `packets_fts USING fts5(info, content='packets', content_rowid='id', tokenize='trigram')`. Verify with a transaction that `MATCH 'telegram'` returns an inserted probe row, then roll back; raise `DependencyError` if unsupported.

- [ ] **Step 4: Implement single-writer batch insertion**

Use WAL mode, foreign keys, transaction per batch and FTS synchronization triggers. The public async caller sends immutable batches to one worker thread; no SQLite connection crosses threads.

- [ ] **Step 5: Implement stable paged queries**

Order by `global_number`, return `PacketPage(rows, total, offset, limit)`, escape FTS quotes, treat an empty Info query as no FTS condition, and join the selected display generation only when it exists.

- [ ] **Step 6: Benchmark the required behavior**

Add a marked benchmark-style test inserting 100,000 summaries and assert a warm `telegram` query completes under 200 ms on the development machine. Record timing for diagnostics without making CI depend on host speed; CI asserts only correctness.

- [ ] **Step 7: Verify and commit**

Run: `python -m pytest tests/unit/services/test_index.py -v && ruff check src tests && mypy src`  
Expected: PASS.

```bash
git add src/packetscope/services/index.py tests/unit/services/test_index.py
git commit -m "Добавить индекс пакетов и поиск по Info"
```

### Task 5: Индексация PCAP/PCAPNG и display filters

**Files:**
- Create: `src/packetscope/services/filtering.py`
- Modify: `src/packetscope/services/tshark.py`
- Test: `tests/unit/services/test_filtering.py`
- Test: `tests/integration/test_open_capture.py`
- Create: `tests/fixtures/telegram-packets.txt`

**Interfaces:**
- Produces: `async TsharkAdapter.stream_file(path: Path) -> AsyncIterator[PacketSummary]`
- Produces: `async DisplayFilterEngine.apply(expression: str, sources: Sequence[CaptureSource]) -> FilterGeneration`
- Produces: `DisplayFilterEngine.cancel_current() -> None`
- Produces: `CaptureSource(path: Path, source_id: str)` and `FilterGeneration(id: int, expression: str, error: str | None)`
- Consumes: `PacketIndex.insert_batch`, `PacketIndex.replace_display_matches`

- [ ] **Step 1: Create a deterministic fixture source**

Store a text2pcap hex fixture containing a valid Ethernet/IPv4/UDP DNS query for `api.telegram.org`, generate `tests/fixtures/telegram.pcapng` through `text2pcap` in the integration fixture setup, and skip only when Wireshark CLI is absent. Проверка ожидает `api.telegram.org` в `_ws.col.Info`, а не в произвольном UDP payload.

- [ ] **Step 2: Write failing open/filter integration tests**

```python
async def test_open_indexes_info_and_applies_tshark_filter(capture_file: Path) -> None:
    packets = [packet async for packet in adapter.stream_file(capture_file)]
    assert any("telegram" in packet.info.casefold() for packet in packets)
    generation = await engine.apply("udp", [CaptureSource(capture_file, "file")])
    assert generation.expression == "udp"
    assert generation.error is None
```

- [ ] **Step 3: Run tests to verify failure**

Run: `python -m pytest tests/unit/services/test_filtering.py tests/integration/test_open_capture.py -v`  
Expected: FAIL because file streaming and filter generations are absent.

- [ ] **Step 4: Implement streaming file ingestion**

Run `tshark -r path -T fields` with the exact field list from Task 2, read with `asyncio.create_subprocess_exec`, batch 500 rows or 75 ms, and publish progress from file bytes read when available.

- [ ] **Step 5: Implement generation-safe filtering**

Increment a monotonic generation ID, validate after 200 ms debounce, limit concurrent TShark workers to `min(4, os.cpu_count() or 1)`, collect `(segment_id, frame.number)` matches, map them to packet IDs, and atomically replace matches. Cancel processes for stale generations and discard late output.

- [ ] **Step 6: Test invalid and rapidly replaced expressions**

Assert `udp &&` returns a Russian syntax message while generation N remains visible; assert generation N+2 wins when N+1 completes afterward.

- [ ] **Step 7: Verify and commit**

Run: `python -m pytest tests/unit/services/test_filtering.py tests/integration/test_open_capture.py -v && ruff check src tests && mypy src`  
Expected: PASS with integration tests skipped only when declared external tools are absent.

```bash
git add src/packetscope/services tests/unit/services/test_filtering.py tests/integration tests/fixtures
git commit -m "Добавить индексацию файлов и display filters"
```

### Task 6: Live-захват и конечный автомат сессии

**Files:**
- Create: `src/packetscope/services/capture.py`
- Modify: `src/packetscope/models.py`
- Modify: `src/packetscope/services/tshark.py`
- Test: `tests/unit/services/test_capture.py`
- Test: `tests/integration/test_capture_process.py`

**Interfaces:**
- Produces: `CaptureState = IDLE | RUNNING | STOPPED | SAVING | LIMIT_REACHED | RESTARTING | FAILED | CLOSING`
- Produces: `async CaptureSession.start(interface: str, capture_filter: str | None) -> None`
- Produces: `async CaptureSession.stop() -> None`
- Produces: `async CaptureSession.continue_capture() -> None`
- Produces: `async CaptureSession.restart(confirm: bool) -> None`
- Produces: `CaptureSession.events() -> AsyncIterator[CaptureEvent]`
- Produces: `CaptureEvent` union of `PacketBatch`, `SegmentClosed`, `StateChanged`, `LimitReached` and `CaptureFailed`

- [ ] **Step 1: Write failing state-transition tests with a fake process**

```python
async def test_stop_continue_keeps_global_history(session: CaptureSession) -> None:
    await session.start("en0", None)
    session.fake_process.emit(packet(number=1))
    await session.stop()
    await session.continue_capture()
    session.fake_process.emit(packet(number=1))
    assert await session.index.global_numbers() == [1, 2]

async def test_restart_requires_confirmation(session: CaptureSession) -> None:
    await session.start("en0", None)
    with pytest.raises(CaptureError, match="подтверждение"):
        await session.restart(confirm=False)
```

- [ ] **Step 2: Run tests to verify failure**

Run: `python -m pytest tests/unit/services/test_capture.py -v`  
Expected: FAIL because `CaptureSession` is undefined.

- [ ] **Step 3: Implement state transitions and serialized commands**

Guard public commands with one `asyncio.Lock`; reject invalid transitions with Russian `CaptureError`; stop with SIGINT, timeout 3 seconds, terminate, timeout 2 seconds, then kill as final fallback.

- [ ] **Step 4: Implement segmented live process**

Use TShark `-i`, optional `-f`, `-w str(session_store.root / "capture.pcapng")`, `-b duration:0.5`, `-b printname:stderr`, `-P`, `-l`, and fields output. Live rows получают глобальный номер приложения и `segment_frame_number=None`, потому что TShark может не печатать `frame.number` при live-захвате. После закрытия сегмента перечитать его через `stream_file`, сопоставить его N кадров с первыми N provisional-строками FIFO, атомарно заполнить `segment_id`/`segment_frame_number` и только затем разрешить Details/display-filter для этих строк.

- [ ] **Step 5: Enforce total session limit**

Poll aggregate PCAPNG+SQLite size every 100 ms. At `>=1_000_000_000` bytes stop capture, emit `LimitReached(total_bytes=total_bytes)`, disable continue, and keep index/details/save available.

- [ ] **Step 6: Test failures and cleanup ordering**

Cover invalid interface, missing permissions, unexpected process exit, stop timeout, limit reached, restart deleting only current session, and closing the process before deleting files.

- [ ] **Step 7: Run integration smoke test**

Run: `python -m pytest tests/integration/test_capture_process.py -v`  
Expected: PASS when a permitted loopback interface exists; otherwise SKIP with the exact missing capability.

- [ ] **Step 8: Verify and commit**

Run: `python -m pytest tests/unit/services/test_capture.py -v && ruff check src tests && mypy src`  
Expected: PASS.

```bash
git add src/packetscope tests/unit/services/test_capture.py tests/integration/test_capture_process.py
git commit -m "Реализовать управление live-захватом"
```

### Task 7: Сохранение snapshot и детали пакета

**Files:**
- Create: `src/packetscope/services/save.py`
- Create: `src/packetscope/services/details.py`
- Test: `tests/unit/services/test_save.py`
- Test: `tests/unit/services/test_details.py`

**Interfaces:**
- Produces: `async SaveService.save(session: CaptureSession, destination: Path, overwrite: bool = False) -> SaveResult`
- Produces: `async PacketDetailsService.load(segment: Path, frame_number: int) -> PacketDetails`
- Produces: `PacketDetails(protocol_tree: tuple[ProtocolNode, ...], hex_lines: tuple[str, ...])`
- Produces: `ProtocolNode(label: str, children: tuple[ProtocolNode, ...])` and `SaveResult(path: Path, packet_count: int, bytes_written: int)`

- [ ] **Step 1: Write failing atomic-save tests**

```python
async def test_save_merges_to_part_then_replaces(tmp_path: Path) -> None:
    destination = tmp_path / "saved.pcapng"
    result = await service.save(session_with_two_segments(), destination)
    assert result.path == destination
    assert destination.exists()
    assert not destination.with_suffix(".pcapng.part").exists()
```

- [ ] **Step 2: Write failing details tests**

Assert the exact TShark command contains `-Y "frame.number == 7" -V -x`; parse protocol indentation into immutable `ProtocolNode` values and keep hex/ASCII lines separate.

- [ ] **Step 3: Run tests to verify failure**

Run: `python -m pytest tests/unit/services/test_save.py tests/unit/services/test_details.py -v`  
Expected: FAIL because both services are undefined.

- [ ] **Step 4: Implement running snapshot rotation and merge**

When running, request a segment rotation and wait at most 1 second for closure. Run `[*tool_paths.mergecap, "-w", str(part_path), *map(str, ordered_segments)]`, validate exit code and nonzero output, then `os.replace`. Refuse overwrite until caller passes `overwrite=True`; delete `.part` on failure.

- [ ] **Step 5: Implement on-demand details with cancellation**

Keep one active details task. Selection change cancels the prior TShark process. Return `DetailsPending` when a live frame belongs to the currently open segment and retry immediately after its closure event.

- [ ] **Step 6: Verify and commit**

Run: `python -m pytest tests/unit/services/test_save.py tests/unit/services/test_details.py -v && ruff check src tests && mypy src`  
Expected: PASS.

```bash
git add src/packetscope/services/save.py src/packetscope/services/details.py tests/unit/services
git commit -m "Добавить сохранение сессий и детали пакетов"
```

### Task 8: Реактивные виджеты фильтров и виртуальная таблица

**Files:**
- Create: `src/packetscope/tui/messages.py`
- Create: `src/packetscope/tui/widgets/filters.py`
- Create: `src/packetscope/tui/widgets/table.py`
- Test: `tests/unit/tui/test_filters.py`
- Test: `tests/unit/tui/test_table.py`

**Interfaces:**
- Produces: `DisplayFilterChanged(expression: str, generation: int)`
- Produces: `InfoSearchChanged(query: str)`
- Produces: `PacketSelected(packet_id: int)`
- Consumes: `PacketIndex.query(display_generation: int | None, info_query: str, page: PageRequest) -> PacketPage`

- [ ] **Step 1: Write failing reactive filter tests**

```python
async def test_info_search_posts_on_each_character(app: FiltersTestApp) -> None:
    async with app.run_test() as pilot:
        await pilot.click("#info-search")
        await pilot.press("t", "e", "l")
        assert app.info_queries == ["t", "te", "tel"]

async def test_display_filter_waits_200_ms_without_enter(app: FiltersTestApp) -> None:
    async with app.run_test() as pilot:
        await pilot.click("#display-filter")
        await pilot.press("u", "d", "p")
        await pilot.pause(0.25)
        assert app.display_queries == ["udp"]
```

- [ ] **Step 2: Run tests to verify failure**

Run: `python -m pytest tests/unit/tui/test_filters.py tests/unit/tui/test_table.py -v`  
Expected: FAIL because widgets are undefined.

- [ ] **Step 3: Implement two independent fields**

Display input owns a resettable 200 ms timer and inline error label; Info input posts every changed value. `Esc` clears only the focused input; `Ctrl+L` clears both. `Enter` returns focus to the table without triggering work.

- [ ] **Step 4: Implement viewport-backed packet table**

Render visible rows plus 20-row overscan, request pages of 250 from `PacketIndex`, keep selection by packet ID across refresh, and never materialize the full result set in Textual widgets.

- [ ] **Step 5: Implement stable protocol styling**

Map TCP, UDP/STUN/TURN, DNS, TLS, ICMP and malformed categories to semantic CSS classes while always retaining protocol text. Test selected-row contrast class precedence.

- [ ] **Step 6: Verify and commit**

Run: `python -m pytest tests/unit/tui/test_filters.py tests/unit/tui/test_table.py -v && ruff check src tests && mypy src`  
Expected: PASS.

```bash
git add src/packetscope/tui tests/unit/tui
git commit -m "Добавить реактивные фильтры и таблицу пакетов"
```

### Task 9: Основной экран TUI варианта C

**Files:**
- Create: `src/packetscope/tui/widgets/details.py`
- Create: `src/packetscope/tui/widgets/actions.py`
- Create: `src/packetscope/tui/screens/packets.py`
- Create: `src/packetscope/tui/packetscope.tcss`
- Test: `tests/unit/tui/test_packet_screen.py`

**Interfaces:**
- Produces: `PacketScreen(session: CaptureSession, index: PacketIndex)`
- Consumes: capture events, filter messages, `PacketDetailsService`, `SaveService`

- [ ] **Step 1: Write failing layout and action tests**

Assert at width 120 the table and details have side-by-side regions; at width 80 details are below the table; assert action labels are `Остановить/Сохранить/Перезапустить` in RUNNING and `Продолжить/Сохранить/Перезапустить` in STOPPED.

- [ ] **Step 2: Run tests to verify failure**

Run: `python -m pytest tests/unit/tui/test_packet_screen.py -v`  
Expected: FAIL because `PacketScreen` is undefined.

- [ ] **Step 3: Implement adaptive composition**

Compose status header, both filter fields, `VirtualPacketTable`, details tree/hex tabs and action footer. At width below 100 switch the details dock from right to bottom; below 90 hide `Length`, then `Destination`, then `Time`, while keeping `No.`, `Protocol` and `Info`.

- [ ] **Step 4: Wire live event batching**

Drain capture events every 75 ms, insert one SQLite batch, update counts/rate/raw/index/total sizes, and refresh only visible table rows. If the event queue grows past 10,000 packets, temporarily extend the UI tick to 100 ms without changing capture behavior.

- [ ] **Step 5: Wire actions and keyboard navigation**

Bind `Space`, `R`, `S`, `F`, `/`, `Enter`, `Tab`, `Q`. Require a modal confirmation containing the packet count and byte size before restart. On save, open a path modal with timestamped default filename and explicit overwrite confirmation.

- [ ] **Step 6: Wire details cancellation and pending state**

Selection posts `PacketSelected`; show a spinner until details arrive; replace it with protocol tree and hex; on selection change cancel the old request without flashing its result.

- [ ] **Step 7: Verify and commit**

Run: `python -m pytest tests/unit/tui/test_packet_screen.py -v && ruff check src tests && mypy src`  
Expected: PASS at both tested terminal sizes.

```bash
git add src/packetscope/tui tests/unit/tui/test_packet_screen.py
git commit -m "Собрать адаптивный экран просмотра пакетов"
```

### Task 10: Команды doctor, interfaces, capture и open

**Files:**
- Create: `src/packetscope/tui/screens/start.py`
- Create: `src/packetscope/tui/app.py`
- Modify: `src/packetscope/cli.py`
- Modify: `src/packetscope/__main__.py`
- Test: `tests/unit/test_cli_commands.py`
- Test: `tests/unit/services/test_doctor.py`

**Interfaces:**
- Produces: `DoctorService.run() -> DoctorReport`
- Produces: `async TsharkAdapter.list_interfaces() -> tuple[CaptureInterface, ...]`
- Produces CLI: `packetscope doctor`, `interfaces`, `capture`, `open PATH`
- Produces: `CaptureInterface(index: int, name: str, description: str)` and `DoctorReport(checks: tuple[DoctorCheck, ...], can_open: bool, can_capture: bool)`

- [ ] **Step 1: Write failing command tests**

```python
def test_capture_without_iface_starts_picker(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(PacketScopeApp, "run_interface_picker", lambda self: calls.append("picker"))
    result = runner.invoke(app, ["capture"])
    assert result.exit_code == 0
    assert calls == ["picker"]

def test_open_rejects_missing_file() -> None:
    result = runner.invoke(app, ["open", "missing.pcapng"])
    assert result.exit_code == 2
    assert "Файл не найден" in result.stdout
```

- [ ] **Step 2: Run tests to verify failure**

Run: `python -m pytest tests/unit/test_cli_commands.py tests/unit/services/test_doctor.py -v`  
Expected: FAIL because commands and doctor report are absent.

- [ ] **Step 3: Implement doctor report**

Report Python, absolute tool paths and versions, FTS5 trigram probe, capture interfaces, BPF/capability access, cache free space and PacketScope version. Use statuses `OK`, `WARN`, `ERROR`; return exit 1 only when the requested workflow cannot run.

- [ ] **Step 4: Implement interface picker and commands**

`interfaces` prints index/name/description; `capture` accepts `--iface`, `--capture-filter`, and a human-size `--max-size`; `open` accepts `.pcap`/`.pcapng` and starts streaming index immediately. Without interface, start the Textual picker and begin capture on selection.

- [ ] **Step 5: Implement Linux permission guidance**

Resolve the actual `dumpcap` path and print `sudo setcap cap_net_raw,cap_net_admin+eip {shlex.quote(str(tool_paths.dumpcap))}`. Do not execute it automatically and do not restart the whole TUI through sudo.

- [ ] **Step 6: Verify and commit**

Run: `python -m pytest tests/unit/test_cli_commands.py tests/unit/services/test_doctor.py -v && ruff check src tests && mypy src`  
Expected: PASS.

```bash
git add src/packetscope tests/unit
git commit -m "Добавить команды запуска и диагностику окружения"
```

### Task 11: Homebrew formula и umbrella-cask

**Files:**
- Create: `packaging/homebrew/Formula/wispwire.rb`
- Create: `packaging/homebrew/Casks/wispwire.rb`
- Create: `packaging/homebrew/test_formula.sh`
- Create: `.github/workflows/release.yml`
- Test: `tests/unit/test_packaging.py`

**Interfaces:**
- Produces macOS install: `brew install --cask kleopadre/tap/wispwire`
- Produces Linux install: `brew install kleopadre/tap/wispwire`
- Consumes stable GitHub tag and source archive SHA-256

- [ ] **Step 1: Write failing structural packaging test**

Parse both Ruby files as text and assert formula contains `depends_on "python@3.13"`, `depends_on "wireshark"`, `virtualenv_install_with_resources`, and a `test do` invoking `packetscope --version`; assert cask contains `depends_on formula: "kleopadre/tap/wispwire"` and `depends_on cask: "wireshark-chmodbpf"`.

- [ ] **Step 2: Run test to verify failure**

Run: `python -m pytest tests/unit/test_packaging.py -v`  
Expected: FAIL because packaging files do not exist.

- [ ] **Step 3: Implement formula source**

Use version `0.1.0`, MIT license, stable GitHub release URL, resource blocks with immutable URLs and SHA-256 for Textual, Typer and their transitive dependencies. Install with Homebrew's Python virtualenv helper and expose `packetscope` in `bin`.

- [ ] **Step 4: Implement umbrella-cask source**

Declare Apple Silicon and macOS requirements, depend on the tap formula and `wireshark-chmodbpf`, use a signed release metadata artifact, and add caveats explaining the administrator prompt and required reboot/login.

- [ ] **Step 5: Implement release workflow**

On tag `v*`, build sdist/wheel, run the full test matrix, publish checksummed GitHub Release assets, calculate the source and Python-resource SHA-256 values, render exact Ruby files, and open an update PR against `KleoPadre/homebrew-tap` using a repository-scoped secret.

- [ ] **Step 6: Audit locally**

Run: `brew style packaging/homebrew/Formula/wispwire.rb packaging/homebrew/Casks/wispwire.rb`
Run: `brew audit --strict --formula packaging/homebrew/Formula/wispwire.rb`
Run: `brew audit --strict --cask packaging/homebrew/Casks/wispwire.rb`
Expected: all commands exit 0.

- [ ] **Step 7: Install in a clean test prefix and commit**

Run: `bash packaging/homebrew/test_formula.sh`  
Expected: `packetscope --version` and `packetscope doctor` succeed; macOS test confirms `wireshark-chmodbpf` is installed or reports that reboot is pending.

```bash
git add packaging .github/workflows/release.yml tests/unit/test_packaging.py
git commit -m "Добавить установку PacketScope через Homebrew"
```

### Task 12: Документация и сквозная приёмка

**Files:**
- Create: `README.md`
- Create: `docs/architecture.md`
- Create: `docs/troubleshooting.md`
- Create: `tests/e2e/test_packetscope_workflow.py`
- Modify: `plan.md`

**Interfaces:**
- Produces: документированный путь от установки до capture/open/save
- Verifies: все 14 критериев готовности из спецификации

- [ ] **Step 1: Write failing end-to-end workflow**

Test with fake capture process and real generated PCAPNG: start session, receive packet with `Info` containing `telegram.org`, apply `udp`, search `telegram`, open details, stop, continue, save two segments, exit and verify temp deletion.

- [ ] **Step 2: Run workflow to identify remaining gaps**

Run: `python -m pytest tests/e2e/test_packetscope_workflow.py -v`  
Expected before final integration: FAIL at the first unconnected application boundary; connect only that boundary, rerun, and repeat until PASS.

- [ ] **Step 3: Write user documentation**

README includes exact Homebrew commands, quick starts, both filter fields, live controls, 1 ГБ limit and screenshots. Troubleshooting covers ChmodBPF reboot, Linux `setcap`, missing interfaces, invalid display filters, disk exhaustion and orphan cleanup.

- [ ] **Step 4: Reconcile original plan**

Mark implemented MVP items in `plan.md`, link the approved spec and implementation plan, and explicitly leave analytics screens and Windows in later milestones.

- [ ] **Step 5: Run full verification**

Run: `python -m pytest -v`  
Expected: all unit, integration and E2E tests pass; only capability-dependent live tests may have explicit SKIP reasons.

Run: `ruff check src tests && ruff format --check src tests && mypy src`  
Expected: zero errors.

Run: `python -m build && twine check dist/*`  
Expected: wheel and sdist build; metadata checks pass.

Run: `packetscope doctor`  
Expected: installed tools, FTS5 and file-open workflow are `OK`; capture permission is either `OK` or gives one exact remediation.

- [ ] **Step 6: Manual visual acceptance**

At 120×35 and 80×24 verify variant C, protocol colors plus text labels, live batch updates, immediate Info search, automatic display-filter error, details cancellation, all bottom-panel states and keyboard-only operation.

- [ ] **Step 7: Commit final documentation**

```bash
git add README.md docs plan.md tests/e2e
git commit -m "Документировать PacketScope и завершить приёмку"
```

## Финальный контроль ветки

- [ ] Run: `git diff --check origin/dev...HEAD` — expected: no output.
- [ ] Run: `git status --short` — expected: clean worktree.
- [ ] Run: `git log --oneline origin/dev..HEAD` — expected: one русскоязычный commit per task.
- [ ] Apply `superpowers:verification-before-completion` before claiming readiness.
- [ ] Apply `superpowers:finishing-a-development-branch` to choose merge, PR or branch cleanup.
