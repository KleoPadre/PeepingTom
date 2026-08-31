# План реализации read-only TUI

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: используйте `superpowers:subagent-driven-development` (рекомендуется) или `superpowers:executing-plans` для поэтапной реализации плана. Шаги отмечаются флажками (`- [ ]`).

**Цель:** заменить табличный вывод `wispwire open` на адаптивный read-only Textual-интерфейс для готовых PCAP/PCAPNG, не меняя исходный файл и не добавляя live-захват.

**Архитектура:** `open` предварительно читает ограниченное число сводок через существующий потоковый адаптер TShark и передаёт их в `WispWireApp` как неизменяемую последовательность `PacketSummary`. `WispWireApp` владеет только отображением: `DataTable` показывает сводки, а выбранная строка обновляет текстовую панель деталей. При ширине менее 120 колонок приложение перестраивает только видимые колонки и добавляет CSS-класс узкой раскладки, перенося детали вниз; при размере меньше 80×24 оно явно сообщает о минимальном размере. SQLite-индекс, поиск, display filter, TShark details и временные session root не входят в этот этап.

**Статус:** исходный scope этого плана завершён. Детали TShark намеренно не входили в него и реализуются отдельным планом `2026-08-31-packet-details.md`; эта запись сохраняет исходные границы и историю плана.

**Технологии:** Python 3.11+, Textual, Typer, Rich, pytest, pytest-asyncio, Ruff, mypy.

**Спецификация:** `docs/superpowers/specs/2026-08-28-wispwire-tui-design.md`

## Общие ограничения

- Код, тесты, документация и пользовательские сообщения — на русском языке; идентификаторы остаются английскими.
- Исходный PCAP/PCAPNG только читается: TUI, CLI и тесты не изменяют и не удаляют его.
- Реальные PCAP/PCAPNG, TShark и live-захват в тестах не запускаются; поток `iter_packet_summaries` подменяется.
- В этой задаче не добавляются SQLite-индексация, FTS-поиск, display filter, live-захват, каталоги сессий, сохранение или сетевые вызовы.
- Зависимость `textual` должна иметь разрешённую лицензии MIT/BSD/Apache/PSF/ISC и ограниченный совместимый диапазон версии в `pyproject.toml`.
- `wispwire open` проверяет путь и доступность TShark до запуска TUI, сохраняет `--limit >= 1`, а ошибки чтения остаются русскими и завершаются кодом 1.
- Тесты запускаются через `.venv/bin/python`; финальные проверки: `pytest`, `ruff check src tests`, `ruff format --check src tests`, `mypy src`, `wispwire open --help` и `git diff --check`.

---

## Структура файлов

| Файл | Ответственность |
| --- | --- |
| `pyproject.toml` | Runtime-зависимость Textual и dev-зависимость pytest-asyncio. |
| `src/wispwire/tui.py` | `WispWireApp`, таблица сводок, панель деталей, горячие клавиши и адаптивная раскладка. |
| `src/wispwire/cli.py` | Подготовка read-only данных для `open` и запуск приложения без изменения проверок пути/TShark. |
| `tests/test_tui.py` | Асинхронные тесты Textual: строки, выбор, клавиатура и узкая раскладка. |
| `tests/test_cli_commands.py` | Тесты границы CLI: передача пакетов в TUI, пустой захват и ошибка адаптера. |
| `README.md` | Запуск `open`, навигация и ограничение read-only TUI. |

### Task 1: зависимость Textual и изолированное отображение пакетов

**Files:**

- Modify: `pyproject.toml`
- Create: `src/wispwire/tui.py`
- Create: `tests/test_tui.py`

**Interfaces:**

- Consumes: `wispwire.packets.PacketSummary`.
- Produces: `WispWireApp(packets: tuple[PacketSummary, ...], source_name: str)`, который поддерживает `run()` и тестовый `run_test()` Textual.

- [x] **Step 1: написать падающие тесты интерфейса**

```python
@pytest.mark.asyncio
async def test_app_shows_packet_fields_and_selected_details() -> None:
    app = WispWireApp((packet(number=7, protocol="UDP"),), "sample.pcapng")
    async with app.run_test() as pilot:
        assert "UDP" in app.query_one("#packets", DataTable).get_row_at(0)
        assert "No.: 7" in app.query_one("#details", Static).renderable


@pytest.mark.asyncio
async def test_app_moves_selection_with_down_key() -> None:
    app = WispWireApp((packet(number=1), packet(number=2)), "sample.pcapng")
    async with app.run_test() as pilot:
        await pilot.press("down")
        assert "No.: 2" in app.query_one("#details", Static).renderable
```

- [x] **Step 2: подтвердить ожидаемое падение**

Run: `.venv/bin/python -m pytest tests/test_tui.py -v`

Expected: FAIL, потому что `wispwire.tui` и зависимость Textual ещё отсутствуют.

- [x] **Step 3: реализовать минимальное приложение**

```python
class WispWireApp(App[None]):
    CSS = """
    #layout { layout: horizontal; }
    #layout.narrow { layout: vertical; }
    #packets { width: 2fr; }
    #details { width: 1fr; }
    """

    def __init__(self, packets: tuple[PacketSummary, ...], source_name: str) -> None:
        super().__init__()
        self._packets = packets
        self._source_name = source_name

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Container(id="layout"):
            yield DataTable(id="packets")
            yield Static(id="details")
        yield Footer()
```

В `on_mount` создать ровно семь колонок из утверждённой модели, добавить строки из `self._packets`, сделать таблицу фокусируемой и отобразить детали первого пакета. В обработчике выбора строки обновлять панель с полями `No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`; строки выводить как обычный текст, без markup. Добавить биндинги `q` → выход и `tab` → смена фокуса.

- [x] **Step 4: проверить Green-цикл**

Run: `.venv/bin/python -m pytest tests/test_tui.py -v`

Expected: PASS.

- [x] **Step 5: закоммитить независимую задачу**

```bash
git add pyproject.toml src/wispwire/tui.py tests/test_tui.py
git commit -m "Добавить read-only TUI пакетов"
```

### Task 2: адаптивная раскладка, минимальный размер и клавиатурная навигация

**Files:**

- Modify: `src/wispwire/tui.py`
- Modify: `tests/test_tui.py`

**Interfaces:**

- Consumes: `WispWireApp` из Task 1 и его идентификаторы `#packets`, `#details`.
- Produces: CSS-классы/правила узкого режима и `#size-warning`, работающие при изменении размера терминала без изменения данных пакетов.

- [x] **Step 1: написать падающие тесты узкого режима**

```python
@pytest.mark.asyncio
async def test_app_shows_minimum_size_warning_below_80x24() -> None:
    app = WispWireApp((packet(),), "sample.pcapng")
    async with app.run_test(size=(79, 23)):
        assert app.query_one("#size-warning", Static).display is True


@pytest.mark.asyncio
async def test_narrow_layout_keeps_number_protocol_and_info_columns() -> None:
    app = WispWireApp((packet(),), "sample.pcapng")
    async with app.run_test(size=(100, 30)):
        table = app.query_one("#packets", DataTable)
        assert [str(column.label) for column in table.ordered_columns] == [
            "No.", "Source", "Protocol", "Info"
        ]
```

- [x] **Step 2: подтвердить ожидаемое падение**

Run: `.venv/bin/python -m pytest tests/test_tui.py -v`

Expected: FAIL, потому что предупреждение и логика размеров отсутствуют.

- [x] **Step 3: реализовать адаптивную раскладку**

```python
def on_resize(self, event: events.Resize) -> None:
    too_small = event.size.width < 80 or event.size.height < 24
    self.query_one("#size-warning", Static).display = too_small
    self._set_table_width(event.size.width >= 120)

def _set_table_width(self, wide: bool) -> None:
    self.query_one("#layout").set_class(not wide, "narrow")
    self._rebuild_table(wide)
```

Добавить `Static` с id `size-warning` и русским текстом «Минимальный размер терминала — 80×24.»; по умолчанию он скрыт. `_rebuild_table` должен сохранить номер выбранной строки, вызвать `DataTable.clear(columns=True)`, добавить точный набор колонок и все значения из `self._packets`, затем восстановить курсор на прежней строке. Для ширины 80–119 оставлять `No.`, `Source`, `Protocol`, `Info` и переносить детали под таблицу классом `narrow`; `Time`, `Destination`, `Length` не добавлять. Для ширины 120+ вернуть семь колонок и боковую панель. Перестроение таблицы не меняет выбранный пакет или данные.

- [x] **Step 4: проверить Green-цикл**

Run: `.venv/bin/python -m pytest tests/test_tui.py -v`

Expected: PASS.

- [x] **Step 5: закоммитить независимую задачу**

```bash
git add src/wispwire/tui.py tests/test_tui.py
git commit -m "Добавить адаптивную раскладку TUI"
```

### Task 3: запуск TUI из read-only команды `open`

**Files:**

- Modify: `src/wispwire/cli.py`
- Modify: `tests/test_cli_commands.py`
- Modify: `README.md`

**Interfaces:**

- Consumes: `iter_packet_summaries(path: Path, tshark_path: Path, limit: int) -> Iterator[PacketSummary]`, `TsharkReadError`, `inspect_tool` и `WispWireApp(packets, source_name)`.
- Produces: `wispwire open PATH [--limit N]`, который запускает TUI с кортежем прочитанных пакетов либо сохраняет существующие русские сообщения об ошибке.

- [x] **Step 1: написать падающие тесты CLI-границы**

```python
def test_open_starts_tui_with_read_only_packet_summaries(monkeypatch, tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.touch()
    started: list[tuple[tuple[PacketSummary, ...], str]] = []
    monkeypatch.setattr("wispwire.cli.iter_packet_summaries", lambda *_: iter([packet()]))
    monkeypatch.setattr("wispwire.cli.WispWireApp", fake_app(started))

    result = CliRunner().invoke(app, ["open", str(capture)])

    assert result.exit_code == 0
    assert started == [((packet(),), "sample.pcapng")]


def test_open_reports_empty_capture_without_starting_tui(monkeypatch, tmp_path: Path) -> None:
    capture = tmp_path / "empty.pcapng"
    capture.touch()
    monkeypatch.setattr("wispwire.cli.iter_packet_summaries", lambda *_: iter(()))
    result = CliRunner().invoke(app, ["open", str(capture)])
    assert "Пакеты не найдены." in result.output
```

- [x] **Step 2: подтвердить ожидаемое падение**

Run: `.venv/bin/python -m pytest tests/test_cli_commands.py -v`

Expected: FAIL, потому что `open` ещё строит Rich-таблицу и не вызывает `WispWireApp`.

- [x] **Step 3: реализовать границу CLI и документацию**

```python
try:
    packets = tuple(iter_packet_summaries(capture_path, status.path, limit))
except TsharkReadError as error:
    console.print(f"Не удалось прочитать захват: {error}")
    raise typer.Exit(code=1) from None

if not packets:
    console.print("Пакеты не найдены.")
    return

WispWireApp(packets, capture_path.name).run()
```

Удалить из `cli.py` только построение Rich-таблицы и `_literal_text`; проверки пути, TShark и кодов ошибок оставить неизменными. В README описать `wispwire open FILE`, клавиши `↑/↓`, `Tab`, `Q`, ограничения read-only режима и то, что поиск/фильтр/live-захват появятся в последующих этапах.

- [x] **Step 4: проверить Green-цикл**

Run: `.venv/bin/python -m pytest tests/test_cli_commands.py tests/test_tui.py -v`

Expected: PASS.

- [x] **Step 5: закоммитить независимую задачу**

```bash
git add src/wispwire/cli.py tests/test_cli_commands.py README.md
git commit -m "Запускать TUI при открытии захвата"
```

### Task 4: итоговая верификация и фиксация статуса

**Files:**

- Modify: `docs/superpowers/plans/2026-08-31-read-only-tui.md`
- Modify: `docs/superpowers/plans/2026-08-28-wispwire-tui.md`

**Interfaces:**

- Consumes: реализованные Tasks 1–3 и команды из `pyproject.toml`.
- Produces: подтверждённый статус этапа 4 в общем плане и commit только с документацией статуса.

- [x] **Step 1: выполнить полный набор проверок**

Run:

```bash
.venv/bin/python -m pytest -v
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src
.venv/bin/wispwire open --help
git diff --check
```

Expected: все команды завершаются кодом 0; `pytest` подтверждает все TUI и CLI-тесты.

- [x] **Step 2: вручную проверить границы этапа**

Проверить `git diff` и код: `open` не пишет в `capture_path`; в изменениях нет `capture`, `dumpcap`, FTS-поиска, display filter и файлов session root; русский текст присутствует в TUI и README.

- [x] **Step 3: отметить выполненные шаги и этап**

Заменить все флажки этого файла на `[x]`. В `docs/superpowers/plans/2026-08-28-wispwire-tui.md` отметить оба пункта этапа 4 как `[x]` и изменить «Ближайшая исполнимая задача» на этап 5: безопасные временные сессии.

- [x] **Step 4: проверить итоговый diff**

Run:

```bash
git diff --check
git diff -- docs/superpowers/plans/2026-08-31-read-only-tui.md docs/superpowers/plans/2026-08-28-wispwire-tui.md
```

Expected: пустой вывод `git diff --check`; меняются только отметки статуса и ближайший этап.

- [x] **Step 5: закоммитить статус этапа**

```bash
git add docs/superpowers/plans/2026-08-31-read-only-tui.md docs/superpowers/plans/2026-08-28-wispwire-tui.md
git commit -m "Отметить выполнение read-only TUI"
```

## Покрытие спецификации

| Требование этапа 4 / релевантный раздел спецификации | Задача плана |
| --- | --- |
| Textual, таблица сводок и панель деталей | Task 1 |
| Минимум 80×24, узкая и широкая раскладка, клавиатура | Task 1–2 |
| Read-only открытие PCAP/PCAPNG через TShark | Task 3 |
| Русские сообщения, отсутствие live/filter/search/session scope | Global Constraints, Task 3–4 |
| Тесты, Ruff, mypy, CLI-help и корректный статус | Task 4 |
