# План реализации безопасных временных сессий WispWire

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: выполнять через `superpowers:subagent-driven-development` по задачам; прогресс отмечать чекбоксами.

**Цель:** добавить безопасное локальное хранилище временных сессий без изменений `open` и read-only TUI.

**Архитектура:** `sessions.py` владеет cache-root, UUID и manifest, регистрацией файлов и расчётом размера. Cleanup просматривает только дочерние каталоги root и удаляет лишь подтверждённые осиротевшие сессии.

**Технологии:** Python 3.11+, `dataclasses`, `json`, `os`, `pathlib`, `uuid`, `datetime`; pytest, Ruff, mypy.

**Спецификация:** `docs/superpowers/specs/2026-09-01-session-storage-design.md`

## Общие ограничения

- Русский язык для кода, тестов, документации и сообщений; английский — только в идентификаторах и форматах.
- Не добавлять `capture`, subprocess, обработчики сигналов, фильтры, изменения `wispwire open` или TUI.
- `manifest.json` имеет `schema_version == 1`, UUID, PID, ISO-8601 UTC-время и относительные owned paths.
- Все цели остаются строго внутри cache-root; символические ссылки не удаляются автоматически.
- Тесты используют `tmp_path` и заглушку PID, без пользовательских cache-каталогов и сигналов.
- Итоговые проверки: pytest, Ruff check/format, mypy и `git diff --check` через `.venv`.

---

## Структура файлов

- `src/wispwire/sessions.py`: модели, cache-root, manifest, размер и очистка.
- `tests/test_sessions.py`: изолированные тесты API и опасных путей.
- `docs/superpowers/plans/2026-08-28-wispwire-tui.md`: отметка этапа 5 после проверок.

### Task 1: создание сессии, manifest и размер

**Файлы:** создать `src/wispwire/sessions.py` и `tests/test_sessions.py`.

**Интерфейсы:** производит `SessionManifest`, `Session`, `SessionSafetyError`, `SessionStorage.default_cache_root()`, `create_session()`, `register_file()` и `session_size()`.

- [x] **Шаг 1: написать падающие тесты cache-root и manifest.**

```python
def test_create_session_writes_valid_manifest(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123)
    session = storage.create_session()
    assert session.path.parent == tmp_path
    assert session.manifest.session_id == session.path.name
    assert (session.path / "manifest.json").is_file()

def test_default_cache_root_uses_xdg_cache_home_on_linux(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert SessionStorage.default_cache_root() == tmp_path / "wispwire" / "sessions"
```

- [x] **Шаг 2: запустить `.venv/bin/python -m pytest -q tests/test_sessions.py`; убедиться в FAIL, так как `wispwire.sessions` отсутствует.**

- [x] **Шаг 3: реализовать минимальный API.**

```python
@dataclass(frozen=True)
class SessionManifest:
    schema_version: int
    session_id: str
    pid: int
    started_at: str
    owned_files: tuple[str, ...]

@dataclass(frozen=True)
class Session:
    path: Path
    manifest: SessionManifest

class SessionStorage:
    @staticmethod
    def default_cache_root() -> Path: ...
    def create_session(self) -> Session: ...
    def register_file(self, session: Session, path: Path) -> Session: ...
    def session_size(self, session: Session) -> int: ...
```

macOS: `Path.home() / "Library/Caches/WispWire/sessions"`; Linux: `XDG_CACHE_HOME` или `Path.home() / ".cache"`, затем `wispwire/sessions`. Создание записывает JSON во временный файл того же каталога и делает `Path.replace`. Регистрация разрешает только обычный файл с лексическим и resolved-путём внутри session root; сохраняет относительный путь без дублей. Размер суммирует regular-файлы, а ссылка или выход из root возбуждают `SessionSafetyError`.

- [x] **Шаг 4: добавить тест регистрации и размера.**

```python
def test_register_file_updates_manifest_and_counts_regular_file(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123)
    session = storage.create_session()
    payload = session.path / "segments" / "part-0001.pcapng"
    payload.parent.mkdir()
    payload.write_bytes(b"abc")
    updated = storage.register_file(session, payload)
    assert updated.manifest.owned_files == ("segments/part-0001.pcapng",)
    assert storage.session_size(updated) >= 3
```

- [x] **Шаг 5: запустить тесты задачи и закоммитить.** Запустить `.venv/bin/python -m pytest -q tests/test_sessions.py`, затем `git add src/wispwire/sessions.py tests/test_sessions.py` и `git commit -m "Добавить хранилище временных сессий"`.

### Task 2: безопасная очистка осиротевших сессий

**Файлы:** изменить `src/wispwire/sessions.py`, `tests/test_sessions.py` и статусный план.

**Интерфейсы:** потребляет API задачи 1; производит `SessionStorage.close_session()` и `cleanup_orphaned_sessions()`.

- [x] **Шаг 1: написать падающие тесты cleanup.**

```python
def test_cleanup_removes_only_valid_orphan(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123, is_pid_alive=lambda _pid: False)
    session = storage.create_session()
    assert storage.cleanup_orphaned_sessions() == (session.path,)
    assert not session.path.exists()

def test_cleanup_skips_session_with_live_pid(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123, is_pid_alive=lambda _pid: True)
    session = storage.create_session()
    assert storage.cleanup_orphaned_sessions() == ()
    assert session.path.is_dir()
```

- [x] **Шаг 2: добавить тест опасных кандидатов:** неверный UUID, некорректный JSON, `owned_files=["../external.txt"]`, символическая ссылка и подменённый manifest; внешний файл должен остаться неизменным, а `close_session()` — отклонить небезопасную сессию.

- [x] **Шаг 3: запустить `.venv/bin/python -m pytest -q tests/test_sessions.py`; убедиться в FAIL, так как cleanup ещё нет.**

- [x] **Шаг 4: реализовать проверяемую очистку.**

```python
def close_session(self, session: Session) -> bool: ...
def cleanup_orphaned_sessions(self) -> tuple[Path, ...]: ...
def _is_safe_session_directory(self, candidate: Path) -> bool: ...
def _read_manifest(self, session_path: Path) -> SessionManifest | None: ...
```

Cleanup вызывает только `cache_root.iterdir()`. До удаления проверяет UUID имени, отсутствие ссылок на пути, containment, валидный manifest и мёртвый PID. Удаление обходит только обычные файлы и каталоги; первая ссылка, ошибка или выход за root оставляют кандидат. `close_session()` повторяет те же проверки.

- [x] **Шаг 5: выполнить проверки.** Последовательно: `.venv/bin/python -m pytest -q tests/test_sessions.py`, `.venv/bin/python -m pytest -q`, `.venv/bin/ruff check src tests`, `.venv/bin/ruff format --check src tests`, `.venv/bin/mypy src`, `git diff --check`; ожидается код 0.

- [x] **Шаг 6: отметить оба пункта этапа 5 как `[x]` и закоммитить.** Использовать `git add src/wispwire/sessions.py tests/test_sessions.py docs/superpowers/plans/2026-08-28-wispwire-tui.md` и `git commit -m "Завершить безопасные временные сессии"`.

## Покрытие спецификации

| Требование | Задача |
| --- | --- |
| Cache-root, UUID и атомарный manifest | 1 |
| Регистрация файлов и размер | 1 |
| Защита от ссылок и выхода за root | 1, 2 |
| Закрытие и cleanup валидной осиротевшей сессии | 2 |
| Защита активного PID и внешних файлов | 2 |
| Unit-тесты и итоговые проверки | 1, 2 |
