# План реализации деталей пакета

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: используйте `superpowers:subagent-driven-development` или `superpowers:executing-plans` для поэтапной реализации. Шаги отмечаются флажками (`- [ ]`).

**Цель:** показать в read-only TUI дерево протоколов и hex/ASCII выбранного кадра.

**Архитектура:** `tshark.py` читает только один кадр и возвращает неизменяемый `PacketDetails`; TUI получает читатель деталей через конструктор и показывает результат или локальную ошибку, не завершая приложение.

**Технологии:** Python 3.11+, Textual, TShark, pytest, Ruff, mypy.

**Спецификация:** `docs/superpowers/specs/2026-08-28-wispwire-tui-design.md`, разделы 6, 8 и 10.

## Общие ограничения

- Код, тесты и пользовательские сообщения — на русском языке; идентификаторы остаются английскими.
- Исходный PCAP/PCAPNG только читается. TShark получает аргументы-список; запрещены `shell=True`, `sudo` и сеть.
- Реальные PCAP/PCAPNG и TShark в тестах не запускаются; вызовы подменяются.
- Обрабатывается только `frame.number == N`; не добавляются индекс, FTS, фильтры, live-захват, сессии или сохранение.
- Ошибка деталей остаётся в панели выбранного пакета и не закрывает TUI.

### Task 1: модель и безопасный адаптер TShark

**Files:**

- Modify: `src/wispwire/packets.py`
- Modify: `src/wispwire/tshark.py`
- Modify: `tests/test_tshark.py`

**Interfaces:** Produces `PacketDetails(protocol_tree: str, hex_ascii: str)`, `build_details_command(tshark_path: Path, capture_path: Path, frame_number: int) -> list[str]` и `read_packet_details(capture_path: Path, tshark_path: Path, frame_number: int, run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> PacketDetails`.

- [x] **Step 1: написать падающие тесты**

```python
def test_build_details_command_reads_only_selected_frame() -> None:
    assert build_details_command(Path("/opt/bin/tshark"), Path("capture.pcapng"), 7) == [
        "/opt/bin/tshark", "-n", "-r", "capture.pcapng", "-Y", "frame.number == 7", "-V", "-x"
    ]

def test_read_packet_details_separates_tree_and_hex() -> None:
    result = completed(stdout="Frame 7: 72 bytes\n\n0000  01 02 03 04   ....\n")
    assert read_packet_details(Path("capture.pcapng"), Path("tshark"), 7, run=lambda *_a, **_k: result) == PacketDetails("Frame 7: 72 bytes", "0000  01 02 03 04   ....")
```

- [x] **Step 2: подтвердить Red-цикл** — `.venv/bin/python -m pytest tests/test_tshark.py -v` должен завершиться FAIL: новых функций ещё нет.

- [x] **Step 3: написать минимальную реализацию**

```python
@dataclass(frozen=True)
class PacketDetails:
    protocol_tree: str
    hex_ascii: str

def build_details_command(tshark_path: Path, capture_path: Path, frame_number: int) -> list[str]:
    return [str(tshark_path), "-n", "-r", str(capture_path), "-Y", f"frame.number == {frame_number}", "-V", "-x"]
```

`read_packet_details` отклоняет номер меньше 1 через `TsharkReadError`, вызывает `run(capture_output=True, text=True, check=False, timeout=5)`, передаёт stderr при ненулевом коде, сообщает по-русски о пустом выводе. Он делит stdout по первой строке с четырьмя шестнадцатеричными цифрами и двумя пробелами; если её нет, возвращает весь stdout как дерево и «Hex/ASCII-дамп отсутствует.».

- [x] **Step 4: подтвердить Green-цикл** — `.venv/bin/python -m pytest tests/test_tshark.py -v` должен завершиться PASS.

- [x] **Step 5: закоммитить** с сообщением `Добавить чтение деталей кадра`.

### Task 2: детали выбранного пакета в TUI

**Files:**

- Modify: `src/wispwire/tui.py`
- Modify: `tests/test_tui.py`

**Interfaces:** Consumes `PacketDetails` и `read_details: Callable[[PacketSummary], PacketDetails]`. Produces `WispWireApp(packets: tuple[PacketSummary, ...], source_name: str, read_details: Callable[[PacketSummary], PacketDetails])`.

- [x] **Step 1: написать падающие тесты**

```python
@pytest.mark.asyncio
async def test_app_shows_tree_and_hex_for_selected_packet() -> None:
    app = WispWireApp((packet(7),), "sample.pcapng", lambda _: PacketDetails("Frame 7", "0000  aa"))
    async with app.run_test():
        text = app.query_one("#details", Static).renderable
        assert "Дерево протоколов:\\nFrame 7" in text
        assert "Hex/ASCII:\\n0000  aa" in text
```

- [x] **Step 2: подтвердить Red-цикл** — `.venv/bin/python -m pytest tests/test_tui.py -v` должен завершиться FAIL.

- [x] **Step 3: написать минимальную реализацию** — добавить обязательный `read_details`; `_show_details` сохраняет семь строк сводки, добавляет секции `Дерево протоколов:` и `Hex/ASCII:`. Перехватывает `TsharkReadError` и `OSError`, заменяя секции строкой `Не удалось загрузить детали: <сообщение>`. Все данные TShark выводятся только через `Text`; новый выбор читает новый кадр.

- [x] **Step 4: подтвердить Green-цикл** — `.venv/bin/python -m pytest tests/test_tui.py -v` должен завершиться PASS.

- [x] **Step 5: закоммитить** с сообщением `Показать детали пакета в TUI`.

### Task 3: CLI-граница, документация и статус

**Files:**

- Modify: `src/wispwire/cli.py`
- Modify: `tests/test_cli_commands.py`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-08-28-wispwire-tui.md`
- Modify: `docs/superpowers/plans/2026-08-31-read-only-tui.md`
- Modify: `docs/superpowers/plans/2026-08-31-packet-details.md`

**Interfaces:** Consumes `read_packet_details(capture_path, tshark_path, frame_number)` и `WispWireApp(..., read_details)`. Produces `open`, передающий TUI замыкание для исходного файла.

- [x] **Step 1: написать падающий тест CLI**

```python
def test_open_passes_capture_to_packet_details_reader(monkeypatch, tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.touch()
    monkeypatch.setattr("wispwire.cli.iter_packet_summaries", lambda *_: iter([packet()]))
    monkeypatch.setattr("wispwire.cli.WispWireApp", fake_app_that_calls_reader)
    assert CliRunner().invoke(app, ["open", str(capture)]).exit_code == 0
    assert read_details_calls == [(capture, Path("/usr/bin/tshark"), 1)]
```

- [x] **Step 2: подтвердить Red-цикл** — `.venv/bin/python -m pytest tests/test_cli_commands.py -v` должен завершиться FAIL.

- [x] **Step 3: написать минимальную реализацию и документацию**

```python
def read_details(packet: PacketSummary) -> PacketDetails:
    return read_packet_details(capture_path, status.path, packet.number)

WispWireApp(packets, capture_path.name, read_details).run()
```

Проверки пути и TShark, ошибки сводок и пустой захват не менять. README описывает дерево TShark и hex/ASCII выбранного кадра, read-only границы и отсутствие замены Wireshark. После проверок отметить текущую задачу и третий пункт этапа 4 как `[x]`; ближайшей задачей остаются безопасные временные сессии.

- [x] **Step 4: выполнить итоговые проверки** — последовательно запустить pytest, Ruff check, Ruff format check, mypy, `wispwire open --help` и проверку пробелов Git; все завершаются кодом 0.

- [x] **Step 5: отметить план и закоммитить** с сообщением `Завершить детали read-only TUI`.

## Покрытие спецификации

| Требование | Задача |
| --- | --- |
| Детали выбранного кадра через TShark | Task 1, Task 3 |
| Дерево протоколов и hex/ASCII в панели | Task 1, Task 2 |
| Ошибка не завершает TUI | Task 2 |
| Read-only исходный файл | Общие ограничения, Task 1, Task 3 |
| Полная проверка и статус этапа 4 | Task 3 |
