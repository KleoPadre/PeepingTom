# План реализации live-захвата WispWire

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: выполнять через \`superpowers:subagent-driven-development\` или \`superpowers:executing-plans\` по задачам; прогресс отмечать чекбоксами.

**Цель:** добавить безопасный программный слой сегментированного live-захвата и команду \`wispwire capture\` без подключения к TUI.

**Архитектура:** \`CaptureSession\` из \`capture.py\` владеет процессом \`dumpcap\`, \`SessionStorage\` и подтверждёнными сегментами. Он строит аргументы без shell, проверяет пути, реализует конечный автомат и сохраняет snapshot через \`mergecap\`; \`cli.py\` остаётся тонким адаптером.

**Технологии:** Python 3.11+, dataclasses, enum, pathlib, subprocess, Typer, Rich, pytest, Ruff, mypy.

**Спецификация:** \`docs/superpowers/specs/2026-09-02-live-capture-design.md\`

## Общие ограничения

- Все тексты, комментарии, документация и тесты — на русском; английский допустим только для идентификаторов и форматов сторонних утилит.
- Не подключать Textual TUI, SQLite, display filter, поиск по Info, обработчики сигналов и реальный захват в тестах.
- \`dumpcap\` и \`mergecap\` запускаются только списком аргументов с \`shell=False\`.
- Временные данные создаются через \`SessionStorage\`; внешние пути, ссылки и дубли не становятся сегментами.
- Пользовательский файл не перезаписывается; сохранение использует соседний \`.part\` и \`Path.replace()\` после успешного \`mergecap\`.
- Лимит по умолчанию — \`1_073_741_824\` байта и относится ко всем owned-файлам session root.
- Итоговые проверки выполняются через \`.venv\`: pytest, Ruff check/format, mypy и \`git diff --check\`.

---

## Структура файлов

- \`src/wispwire/capture.py\`: состояния, процессы, сегменты, лимит и snapshot.
- \`tests/test_capture.py\`: изолированные проверки API с фальшивыми процессами и \`tmp_path\`.
- \`src/wispwire/cli.py\`: команда \`capture\`.
- \`tests/test_cli_commands.py\`: проверки команды через \`CliRunner\`.
- \`README.md\`: запуск и границы этапа.
- \`docs/superpowers/plans/2026-08-28-wispwire-tui.md\`: отметка этапа 6 после итоговой проверки.

### Task 1: команды захвата и базовый конечный автомат

**Файлы:**
- Создать: \`src/wispwire/capture.py\`.
- Создать: \`tests/test_capture.py\`.

**Интерфейсы:** производит \`CaptureState\`, \`CaptureError\`, \`build_dumpcap_command()\`, \`build_mergecap_command()\` и \`CaptureSession.start()\` / \`stop()\`.

- [ ] **Шаг 1: написать падающие тесты аргументов и старта.**

\`\`\`python
def test_build_dumpcap_command_segments_every_half_second(tmp_path: Path) -> None:
    assert build_dumpcap_command(Path("/opt/bin/dumpcap"), "en0", tmp_path / "segment") == [
        "/opt/bin/dumpcap", "-i", "en0", "-w", str(tmp_path / "segment"),
        "-b", "duration:0.5", "-b", "printname:stdout",
    ]

def test_start_creates_session_and_starts_dumpcap(tmp_path: Path) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    capture = CaptureSession(
        Path("/opt/bin/dumpcap"), Path("/opt/bin/mergecap"), "en0",
        storage=SessionStorage(cache_root=tmp_path, pid=123),
        popen=recording_popen(calls),
    )
    capture.start()
    assert capture.state is CaptureState.RUNNING
    assert capture.session is not None
    assert calls[0][0][0] == build_dumpcap_command(
        Path("/opt/bin/dumpcap"), "en0", capture.session.path / "segment"
    )
\`\`\`

- [ ] **Шаг 2: запустить тесты и убедиться в ожидаемом FAIL.**

Запустить: \`.venv/bin/python -m pytest -q tests/test_capture.py -k 'dumpcap_command or start_creates'\`.

Ожидаемый результат: импорт \`wispwire.capture\` не найден.

- [ ] **Шаг 3: реализовать минимальные типы, команды и запуск.**

\`\`\`python
class CaptureState(StrEnum):
    RUNNING = "running"
    STOPPED = "stopped"
    LIMIT_REACHED = "limit_reached"
    FAILED = "failed"
    CLOSED = "closed"

class CaptureError(RuntimeError):
    """Live-захват нельзя безопасно продолжить."""

def build_dumpcap_command(
    dumpcap_path: Path, interface: str, output_base: Path
) -> list[str]: ...

def build_mergecap_command(
    mergecap_path: Path, output_path: Path, segments: tuple[Path, ...]
) -> list[str]: ...

class CaptureSession:
    def __init__(
        self, dumpcap_path: Path, mergecap_path: Path, interface: str, *,
        storage: SessionStorage, max_size: int = 1_073_741_824,
        popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
\`\`\`

\`start()\` разрешён только из исходного \`stopped\`, вызывает \`storage.create_session()\`, открывает stdout/stderr как текстовые PIPE и при \`OSError\` устанавливает \`failed\`, затем выбрасывает \`CaptureError\`. \`stop()\` разрешён только из \`running\`, завершает процесс, ожидает его и меняет состояние на \`stopped\`; ненулевой код означает \`failed\` и \`CaptureError\`.

- [ ] **Шаг 4: выполнить тесты задачи.**

Запустить: \`.venv/bin/python -m pytest -q tests/test_capture.py\`.

Ожидаемый результат: PASS для новых тестов.

- [ ] **Шаг 5: зафиксировать первый независимый результат.**

\`\`\`bash
git add src/wispwire/capture.py tests/test_capture.py
git commit -m "Добавить основу live-захвата"
\`\`\`

### Task 2: безопасные закрытые сегменты, лимит и stop/continue

**Файлы:**
- Изменить: \`src/wispwire/capture.py\`.
- Изменить: \`tests/test_capture.py\`.

**Интерфейсы:** потребляет \`CaptureSession.start()\` и \`SessionStorage\`; производит \`collect_closed_segments()\`, \`continue_capture()\`, \`segments\` и \`state\`.

- [ ] **Шаг 1: написать падающие тесты закрытых сегментов, лимита и продолжения.**

\`\`\`python
def test_collect_closed_segment_registers_only_regular_file(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    segment = capture.session.path / "segment_00001_20260902000000.pcapng"
    segment.write_bytes(b"pcapng")
    capture.process.stdout = iter([f"{segment}\n"])
    capture.collect_closed_segments()
    assert capture.segments == (segment,)
    assert capture.session.manifest.owned_files == (segment.name,)

def test_limit_stops_capture_and_blocks_continue(tmp_path: Path) -> None:
    capture = started_capture(tmp_path, max_size=1)
    segment = capture.session.path / "segment_00001_20260902000000.pcapng"
    segment.write_bytes(b"xx")
    capture.process.stdout = iter([f"{segment}\n"])
    capture.collect_closed_segments()
    assert capture.state is CaptureState.LIMIT_REACHED
    with pytest.raises(CaptureError, match="лимит"):
        capture.continue_capture()
\`\`\`

- [ ] **Шаг 2: запустить тесты и убедиться в ожидаемом FAIL.**

Запустить: \`.venv/bin/python -m pytest -q tests/test_capture.py -k 'closed_segment or limit'\`.

Ожидаемый результат: методов \`collect_closed_segments()\` и \`continue_capture()\` нет.

- [ ] **Шаг 3: реализовать обработку stdout и переходы.**

\`\`\`python
@property
def segments(self) -> tuple[Path, ...]: ...

def collect_closed_segments(self) -> tuple[Path, ...]: ...
def continue_capture(self) -> None: ...
\`\`\`

\`collect_closed_segments()\` читает только строки stdout текущего процесса, нормализует имя как \`Path\`, отклоняет путь вне \`self.session.path\`, ссылку, несуществующий или не-regular файл и дубль. Каждый безопасный сегмент регистрируется \`storage.register_file()\`. После каждой регистрации проверяется \`storage.session_size()\`; при превышении \`max_size\` вызывается штатная остановка и устанавливается \`limit_reached\`. \`continue_capture()\` разрешён только из \`stopped\`, оставляет сегменты и manifest и запускает новый \`dumpcap\` в том же каталоге.

- [ ] **Шаг 4: расширить тесты опасных путей и истории.**

\`\`\`python
def test_collect_closed_segment_rejects_path_outside_session(tmp_path: Path) -> None:
    capture = started_capture(tmp_path)
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"keep")
    capture.process.stdout = iter([f"{outside}\n"])
    with pytest.raises(CaptureError, match="сессии"):
        capture.collect_closed_segments()
    assert outside.read_bytes() == b"keep"
    assert capture.state is CaptureState.FAILED

def test_continue_keeps_confirmed_segment_history(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    capture.continue_capture()
    assert capture.state is CaptureState.RUNNING
    assert len(capture.segments) == 1
\`\`\`

- [ ] **Шаг 5: выполнить все тесты модуля и зафиксировать.**

\`\`\`bash
.venv/bin/python -m pytest -q tests/test_capture.py
git add src/wispwire/capture.py tests/test_capture.py
git commit -m "Добавить сегментацию live-захвата"
\`\`\`

### Task 3: snapshot, restart и безопасное закрытие

**Файлы:**
- Изменить: \`src/wispwire/capture.py\`.
- Изменить: \`tests/test_capture.py\`.

**Интерфейсы:** потребляет закрытые \`segments\`; производит \`save()\`, \`restart()\` и \`close()\`.

- [ ] **Шаг 1: написать падающие тесты сохранения и перезапуска.**

\`\`\`python
def test_save_merges_segments_to_new_destination(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    destination = tmp_path / "saved.pcapng"
    capture.save(destination)
    assert destination.read_bytes() == b"merged"
    assert not (tmp_path / "saved.pcapng.part").exists()

def test_save_does_not_overwrite_existing_file(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    destination = tmp_path / "saved.pcapng"
    destination.write_bytes(b"existing")
    with pytest.raises(CaptureError, match="уже существует"):
        capture.save(destination)
    assert destination.read_bytes() == b"existing"

def test_restart_creates_new_session_after_confirmed_close(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    old_session = capture.session
    capture.restart()
    assert capture.session != old_session
    assert capture.segments == ()
    assert capture.state is CaptureState.RUNNING
\`\`\`

- [ ] **Шаг 2: запустить тесты и убедиться в ожидаемом FAIL.**

Запустить: \`.venv/bin/python -m pytest -q tests/test_capture.py -k 'save or restart'\`.

Ожидаемый результат: методов \`save()\` и \`restart()\` нет.

- [ ] **Шаг 3: реализовать snapshot и освобождение сессии.**

\`\`\`python
def save(self, destination: Path) -> Path: ...
def restart(self) -> None: ...
def close(self) -> bool: ...
\`\`\`

\`save()\` требует хотя бы один сегмент и отсутствующий destination. В \`running\` он вызывает \`stop()\`, собирает последние сегменты, запускает \`mergecap\` в \`.part\`, а после returncode 0 переносит \`.part\` в destination. Если захват был running, \`continue_capture()\` вызывается лишь после успешного snapshot. При ошибке \`.part\` удаляется, исходные сегменты остаются. \`restart()\` разрешён из \`stopped\`, \`failed\` и \`limit_reached\`; при \`storage.close_session() == False\` выбрасывает \`CaptureError\`, иначе сбрасывает историю и запускает новую сессию. \`close()\` останавливает процесс, безопасно закрывает только собственную сессию и устанавливает \`closed\`.

- [ ] **Шаг 4: добавить тесты ошибок mergecap и cleanup.**

\`\`\`python
def test_save_removes_part_and_preserves_segments_when_mergecap_fails(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(
        tmp_path, merge_result=completed("", "merge error", 1)
    )
    destination = tmp_path / "saved.pcapng"
    with pytest.raises(CaptureError, match="merge error"):
        capture.save(destination)
    assert not destination.exists()
    assert capture.segments[0].exists()

def test_close_does_not_remove_session_when_storage_rejects_it(tmp_path: Path) -> None:
    capture = stopped_capture_with_segment(tmp_path)
    capture.storage.close_session = lambda _: False
    with pytest.raises(CaptureError, match="не удалось"):
        capture.close()
\`\`\`

- [ ] **Шаг 5: выполнить тесты модуля и зафиксировать.**

\`\`\`bash
.venv/bin/python -m pytest -q tests/test_capture.py
git add src/wispwire/capture.py tests/test_capture.py
git commit -m "Добавить сохранение live-сессии"
\`\`\`

### Task 4: команда CLI, документация и итоговая проверка

**Файлы:**
- Изменить: \`src/wispwire/cli.py\`.
- Изменить: \`tests/test_cli_commands.py\`.
- Изменить: \`README.md\`.
- Изменить: \`docs/superpowers/plans/2026-08-28-wispwire-tui.md\`.

**Интерфейсы:** потребляет \`CaptureSession\`, \`CaptureError\` и \`inspect_tool()\`; производит \`wispwire capture --iface\` и статус этапа 6.

- [ ] **Шаг 1: написать падающие CLI-тесты.**

\`\`\`python
def test_capture_reports_missing_dumpcap(monkeypatch) -> None:
    monkeypatch.setattr(
        "wispwire.cli.inspect_tool",
        lambda name: ToolStatus(name, None, None, "не найден"),
    )
    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])
    assert result.exit_code == 1
    assert "dumpcap недоступен" in result.output

def test_capture_starts_session_for_known_interface(monkeypatch) -> None:
    started: list[str] = []
    monkeypatch.setattr("wispwire.cli.list_interfaces", lambda: ("en0",))
    monkeypatch.setattr("wispwire.cli.CaptureSession", fake_capture_session(started))
    monkeypatch.setattr("wispwire.cli.inspect_tool", available_capture_tools)
    result = CliRunner().invoke(app, ["capture", "--iface", "en0"])
    assert result.exit_code == 0
    assert started == ["en0"]
\`\`\`

- [ ] **Шаг 2: запустить тесты и убедиться в ожидаемом FAIL.**

Запустить: \`.venv/bin/python -m pytest -q tests/test_cli_commands.py -k capture\`.

Ожидаемый результат: CLI не знает команду \`capture\`.

- [ ] **Шаг 3: добавить минимальную команду и русскую документацию.**

\`\`\`python
@app.command()
def capture(
    interface: str = typer.Option(..., "--iface", help="Интерфейс для live-захвата."),
) -> None: ...
\`\`\`

Команда отдельно проверяет \`dumpcap\` и \`mergecap\` через \`inspect_tool()\`, интерфейс — через \`list_interfaces()\`. При ошибке печатает русское сообщение и завершает работу кодом 1 или 2 до создания сессии. При успехе создаёт \`CaptureSession\`, вызывает \`start()\` и печатает статус программного слоя; README прямо сообщает, что управление из TUI появится на этапе 7.

- [ ] **Шаг 4: отметить этап 6 после проверок.**

Заменить оба \`[ ]\` этапа 6 в \`docs/superpowers/plans/2026-08-28-wispwire-tui.md\` на \`[x]\`, добавив ссылки на коммиты задач 1–3. Пункты этапов 7–8 не менять.

- [ ] **Шаг 5: выполнить полный набор проверок.**

\`\`\`bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src
.venv/bin/wispwire capture --help
git diff --check
\`\`\`

Ожидаемый результат: все команды завершаются кодом 0.

- [ ] **Шаг 6: проверить дифф и зафиксировать этап.**

\`\`\`bash
git diff --check
git status --short
git add src/wispwire/cli.py tests/test_cli_commands.py README.md docs/superpowers/plans/2026-08-28-wispwire-tui.md
git commit -m "Завершить live-захват"
\`\`\`

## Покрытие спецификации

| Требование | Задача |
| --- | --- |
| Команды внешних программ без shell и процесс dumpcap | 1 |
| Сегменты 500 мс, безопасные пути и лимит 1 ГБ | 2 |
| stop/continue и недопустимые переходы | 1, 2 |
| snapshot через mergecap, .part, restart и cleanup | 3 |
| CLI, русские ошибки, документация и статус этапа | 4 |
| Unit-тесты и итоговые проверки | 1–4 |
