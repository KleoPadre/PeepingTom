# Основа CLI: диагностика и интерфейсы — план реализации

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: используйте `superpowers:subagent-driven-development` для реализации плана по задачам. Шаги отмечаются флажками (`- [ ]`).

**Цель:** создать устанавливаемый пакет WispWire с командами `doctor` и `interfaces`, которые безопасно диагностируют внешний набор Wireshark без запуска реального захвата.

**Архитектура:** `cli.py` остаётся тонким слоем Typer. Модуль `diagnostics.py` собирает неизменяемые результаты проверок и не печатает в терминал; `wireshark.py` инкапсулирует поиск программ и безопасные вызовы через список аргументов. Rich только отображает готовые результаты. Это создаёт проверяемую основу для будущих `open` и `capture`.

**Стек:** Python 3.11+, Typer, Rich, pytest, Ruff, mypy.

**Спецификация:** `docs/superpowers/specs/2026-08-28-wispwire-tui-design.md`

## Глобальные ограничения

- Рабочая ветка — `dev`; `main` получает только проверенные рабочие версии с семантическим тегом.
- Все пользовательские тексты, документация и комментарии — на русском языке.
- Не запускать реальный захват и не требовать `sudo` для диагностики или тестов.
- Не использовать `shell=True`; команды внешних программ передавать списком аргументов.
- Не добавлять PCAP/PCAPNG и реальные сетевые данные в Git.
- Эта поставка ограничена каркасом, `doctor` и `interfaces`; TUI, чтение PCAP и capture будут отдельными планами после проверки основы.

---

### Task 1: Настроить пакет и инструменты качества

**Файлы:**

- Создать: `pyproject.toml`
- Создать: `src/wispwire/__init__.py`
- Создать: `src/wispwire/cli.py`
- Создать: `tests/test_cli.py`
- Создать: `README.md`

**Интерфейсы:**

- Производит entry point `wispwire = "wispwire.cli:app"` и объект `app: typer.Typer`.
- Потребляет Python 3.11+, Typer и Rich.

- [ ] **Шаг 1: Написать падающий тест справки CLI**

```python
from typer.testing import CliRunner

from wispwire.cli import app


def test_cli_shows_russian_help() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "WispWire" in result.stdout
    assert "диагностики" in result.stdout
```

- [ ] **Шаг 2: Убедиться, что тест падает из-за отсутствия модуля**

Запустить: `python -m pytest tests/test_cli.py::test_cli_shows_russian_help -v`.

Ожидаемый результат: `ModuleNotFoundError: No module named 'wispwire'`.

- [ ] **Шаг 3: Реализовать минимальный пакет и конфигурацию**

Создать `pyproject.toml` с build backend Hatchling, зависимостями `typer>=0.12,<1` и `rich>=13,<15`, группой `dev` для pytest, Ruff и mypy, `requires-python = ">=3.11"`, package-dir `src`, настройкой pytest `pythonpath = ["src"]` и console-script `wispwire = "wispwire.cli:app"`. В `cli.py` создать `app = typer.Typer(help="WispWire — терминальная утилита для диагностики сетевого анализа.")` и блок `if __name__ == "__main__": app()`. В README описать установку зависимостей и команды проверок.

- [ ] **Шаг 4: Проверить зелёный тест и базовые проверки**

Запустить: `python -m pytest tests/test_cli.py::test_cli_shows_russian_help -v`, затем `ruff check src tests`, `ruff format --check src tests` и `mypy src`.

Ожидаемый результат: все команды завершаются успешно.

- [ ] **Шаг 5: Закоммитить независимую задачу**

```bash
git add pyproject.toml README.md src/wispwire tests/test_cli.py
git commit -m "Добавить основу CLI WispWire"
```

### Task 2: Безопасно обнаруживать утилиты Wireshark

**Файлы:**

- Создать: `src/wispwire/wireshark.py`
- Создать: `tests/test_wireshark.py`

**Интерфейсы:**

- Производит `ToolStatus(name: str, path: Path | None, version: str | None, error: str | None)`.
- Производит `inspect_tool(name: str, which: Callable[[str], str | None] = shutil.which, run: Callable[..., CompletedProcess[str]] = subprocess.run) -> ToolStatus`.
- Потребляется `diagnostics.collect_doctor_report`.

- [ ] **Шаг 1: Написать падающие тесты найденной и отсутствующей утилиты**

```python
from pathlib import Path

from wispwire.wireshark import inspect_tool


def test_inspect_tool_returns_version_for_found_program() -> None:
    status = inspect_tool("tshark", which=lambda _: "/opt/bin/tshark", run=fake_version_run)
    assert status.path == Path("/opt/bin/tshark")
    assert status.version == "4.4.0"
    assert status.error is None


def test_inspect_tool_reports_missing_program() -> None:
    status = inspect_tool("dumpcap", which=lambda _: None)
    assert status.path is None
    assert status.error == "утилита не найдена в PATH"
```

Добавить `fake_version_run`, возвращающий `CompletedProcess(["tshark", "--version"], 0, "TShark (Wireshark) 4.4.0\n", "")`.

- [ ] **Шаг 2: Проверить ожидаемое падение**

Запустить: `python -m pytest tests/test_wireshark.py -v`.

Ожидаемый результат: ошибка импорта `wispwire.wireshark`.

- [ ] **Шаг 3: Написать минимальную реализацию**

Использовать `shutil.which`; версию запрашивать только как `[путь, "--version"]` с `capture_output=True`, `text=True`, `check=False`, `timeout=5`. Первую строку stdout разобрать регулярным выражением `([0-9]+(?:\.[0-9]+)+)`. При ненулевом коде, тайм-ауте или нераспознанной версии возвращать `error`, не выбрасывая исключение.

- [ ] **Шаг 4: Проверить весь модуль**

Запустить: `python -m pytest tests/test_wireshark.py -v`, `ruff check src tests`, `ruff format --check src tests`, `mypy src`.

Ожидаемый результат: все команды успешны.

- [ ] **Шаг 5: Закоммитить независимую задачу**

```bash
git add src/wispwire/wireshark.py tests/test_wireshark.py
git commit -m "Добавить проверку утилит Wireshark"
```

### Task 3: Сформировать отчёт диагностики и список интерфейсов

**Файлы:**

- Создать: `src/wispwire/diagnostics.py`
- Создать: `tests/test_diagnostics.py`
- Изменить: `src/wispwire/wireshark.py`

**Интерфейсы:**

- Потребляет `ToolStatus` и `inspect_tool`.
- Производит `DoctorReport(python_version: str, wispwire_version: str, tools: tuple[ToolStatus, ...], interfaces: tuple[str, ...], capture_warning: str | None)`.
- Производит `collect_doctor_report(...) -> DoctorReport` и `list_interfaces(...) -> tuple[str, ...]`.
- Потребляется командами CLI в следующей задаче.

- [ ] **Шаг 1: Написать падающие тесты отчёта и разбора интерфейсов**

```python
from wispwire.diagnostics import collect_doctor_report, list_interfaces


def test_list_interfaces_parses_dumpcap_output() -> None:
    output = "1. en0 (Wi-Fi)\n2. lo0 (Loopback)\n"
    assert list_interfaces(run=fake_interfaces_run) == ("en0", "lo0")


def test_doctor_warns_when_capture_tools_are_missing() -> None:
    report = collect_doctor_report(inspect=fake_missing_inspect, interfaces=lambda: ())
    assert report.capture_warning == "live-захват недоступен: установите dumpcap"
```

- [ ] **Шаг 2: Убедиться, что тесты падают**

Запустить: `python -m pytest tests/test_diagnostics.py -v`.

Ожидаемый результат: ошибка импорта `wispwire.diagnostics`.

- [ ] **Шаг 3: Реализовать чистый слой отчёта**

`list_interfaces` запускает только `[dumpcap_path, "-D"]`, не вызывает `sudo`, отбрасывает описания в скобках и возвращает пустой кортеж при ошибке. `collect_doctor_report` проверяет `tshark`, `dumpcap` и `mergecap`, получает интерфейсы лишь при найденном `dumpcap`, возвращает версии Python/WispWire и одно ясное предупреждение о невозможности live-захвата.

- [ ] **Шаг 4: Проверить тесты и статический анализ**

Запустить: `python -m pytest tests/test_diagnostics.py -v`, `ruff check src tests`, `ruff format --check src tests`, `mypy src`.

Ожидаемый результат: все команды успешны.

- [ ] **Шаг 5: Закоммитить независимую задачу**

```bash
git add src/wispwire/diagnostics.py src/wispwire/wireshark.py tests/test_diagnostics.py
git commit -m "Добавить отчёт диагностики окружения"
```

### Task 4: Предоставить команды `doctor` и `interfaces`

**Файлы:**

- Изменить: `src/wispwire/cli.py`
- Создать: `tests/test_cli_commands.py`
- Изменить: `README.md`

**Интерфейсы:**

- Потребляет `collect_doctor_report() -> DoctorReport` и `list_interfaces() -> tuple[str, ...]`.
- Производит команды `wispwire doctor` и `wispwire interfaces`.

- [ ] **Шаг 1: Написать падающие тесты команд**

```python
from typer.testing import CliRunner

from wispwire.cli import app


def test_doctor_prints_tool_statuses(monkeypatch) -> None:
    monkeypatch.setattr("wispwire.cli.collect_doctor_report", fake_report)
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "tshark" in result.stdout
    assert "OK" in result.stdout


def test_interfaces_reports_no_available_interfaces(monkeypatch) -> None:
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ())
    result = CliRunner().invoke(app, ["interfaces"])
    assert result.exit_code == 0
    assert "Интерфейсы не найдены" in result.stdout
```

- [ ] **Шаг 2: Убедиться, что тесты падают из-за отсутствия команд**

Запустить: `python -m pytest tests/test_cli_commands.py -v`.

Ожидаемый результат: тесты не находят команды `doctor` и `interfaces`.

- [ ] **Шаг 3: Реализовать команды и отображение Rich**

Добавить Typer-команды с русскими описаниями. `doctor` печатает заголовок, таблицу утилит со статусом `OK` или `ОШИБКА`, интерфейсы и предупреждение. `interfaces` печатает нумерованный список или `Интерфейсы не найдены. Проверьте dumpcap и права доступа.`. Команды не изменяют систему и не запускают захват.

- [ ] **Шаг 4: Проверить полный цикл**

Запустить: `python -m pytest -v`, `ruff check src tests`, `ruff format --check src tests`, `mypy src`, `python -m wispwire.cli doctor`.

Ожидаемый результат: тесты и статические проверки успешны; последняя команда возвращает понятный диагностический вывод и не требует привилегий.

- [ ] **Шаг 5: Закоммитить независимую задачу**

```bash
git add src/wispwire/cli.py tests/test_cli_commands.py README.md
git commit -m "Добавить команды doctor и interfaces"
```

### Task 5: Проверить этап перед переходом к чтению файлов

**Файлы:**

- Изменить: `README.md`
- Изменить: `docs/superpowers/plans/2026-08-28-foundation-doctor-interfaces.md`

**Интерфейсы:**

- Потребляет установленный entry point `wispwire`.
- Производит зафиксированный результат этапа и запись проверок для следующего плана (`open` + потоковое чтение через `tshark`).

- [ ] **Шаг 1: Добавить проверку поставляемого entry point**

В README описать установку в изолированное окружение `python -m pip install -e ".[dev]"` и команды `wispwire --help`, `wispwire doctor`, `wispwire interfaces`.

- [ ] **Шаг 2: Проверить установленную команду**

Запустить: `python -m pip install -e ".[dev]"`, затем `wispwire --help`, `wispwire doctor`, `wispwire interfaces`.

Ожидаемый результат: каждая команда завершается кодом 0; при отсутствии Wireshark выводит диагностическую ошибку, а не traceback.

- [ ] **Шаг 3: Провести итоговые автоматические проверки**

Запустить: `python -m pytest -v`, `ruff check src tests`, `ruff format --check src tests`, `mypy src`.

Ожидаемый результат: все проверки успешны.

- [ ] **Шаг 4: Обновить отметки и закоммитить этап**

Отметить выполненные шаги только после получения фактических результатов. Закоммитить README и план отдельным коммитом:

```bash
git add README.md docs/superpowers/plans/2026-08-28-foundation-doctor-interfaces.md
git commit -m "Документировать первый этап разработки"
```

## Последовательность следующих малых планов

1. `open`: потоковый импорт полей `tshark` и модели пакета без TUI.
2. SQLite-индекс, пагинация и поиск `Info`.
3. Первое read-only TUI для открытия файла и details через `tshark -V`.
4. Сессии и безопасная очистка временных данных.
5. Сегментированный live-захват, лимит размера, stop/continue/restart/save.
6. Display filter и его поколения для файлов и закрытых сегментов.
7. Адаптивная TUI-раскладка, горячие клавиши и TUI-тесты.
8. Homebrew tap, CI и ручные smoke-проверки платформ.
