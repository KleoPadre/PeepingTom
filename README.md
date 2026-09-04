# WispWire

WispWire — терминальная утилита для диагностики сетевого анализа.

## Установка

### Homebrew

Основной пользовательский способ установки:

```bash
brew install kleopadre/tap/wispwire
wispwire doctor
```

Эта команда устанавливает WispWire, Python runtime-зависимости и Wireshark CLI
(`tshark`, `dumpcap`, `mergecap`). После установки пользователь запускает
WispWire обычной командой из терминала:

```bash
wispwire capture --iface en0
wispwire open ~/Downloads/capture.pcapng
```

WispWire не устанавливает и не запускает фоновый сервис. `brew services` для
него не используется: все команды выполняются явно из терминала.

На macOS список интерфейсов может быть пустым, если системе не хватает прав на
BPF-устройства. Это не Python-зависимость WispWire, а системное разрешение
packet capture. `wispwire doctor` явно покажет такую проблему и команду для её
исправления через Homebrew:

```bash
brew install --cask wireshark-chmodbpf
```

### Разработка из исходников

Создайте виртуальное окружение и установите пакет с зависимостями разработки:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Если окружение уже создано, используйте его интерпретатор:

```bash
.venv/bin/python -m pip install -e '.[dev]'
```

## Проверки

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src
```

Проверить поставляемую команду можно так:

```bash
wispwire --help
wispwire doctor
wispwire interfaces
```

## Диагностика окружения

Проверить наличие `tshark`, `dumpcap`, `mergecap`, доступность live-захвата и
SQLite FTS5 trigram, требуемый для индекса и поиска по `Info`:

```bash
.venv/bin/wispwire doctor
```

Посмотреть интерфейсы, которые видит `dumpcap`:

```bash
.venv/bin/wispwire interfaces
```

Эти команды только читают сведения об окружении и не требуют `sudo`. Права могут
понадобиться позднее, при запуске live-захвата.

Если `doctor` сообщает об ошибке SQLite FTS5 trigram, просмотр готовых захватов
остаётся доступным, но индекс и поиск по `Info` не будут созданы.

## Открытие готового захвата

Открыть готовый захват в read-only TUI можно так:

```bash
.venv/bin/wispwire open ~/Downloads/capture.pcapng
.venv/bin/wispwire open ~/Downloads/capture.pcap --limit 500
.venv/bin/wispwire open ~/Downloads/capture.pcapng --filter "udp"
```

TUI не изменяет исходный файл: `tshark` читает только сводки и по выбранному
кадру показывает дерево протоколов и hex/ASCII-дамп. Display filter передаётся
в TShark через `-Y` без переписывания выражения.

Используйте `↑` и `↓` для выбора пакета, `F` для поля display filter, `Esc` для
очистки активного поля, `Tab` для смены фокуса и `Q` для выхода. WispWire не
заменяет Wireshark.

## Live-захват

Запустить сегментированный live-захват на известном `dumpcap` интерфейсе можно
так:

```bash
.venv/bin/wispwire capture --iface en0
```

Перед стартом команда проверяет `dumpcap`, `mergecap` и выбранный интерфейс.
Она создаёт временную сессию только после этих проверок и открывает live-TUI.
В таблицу попадают пакеты только из подтверждённо закрытых сегментов.

Горячие клавиши live-TUI:

- `S` — остановить захват, сохранить результат и открыть его в файловом TUI;
- `Q` — остановить захват и выйти без открытия файлового TUI;
- `C` — продолжить остановленный захват;
- `R` — перезапустить захват;
- `W` — сохранить snapshot без остановки захвата;
- `F` — перейти в поле display filter;
- `Esc` — очистить активное поле фильтра;
- `Tab` — сменить фокус.

Результаты `S` и `W` сохраняются в `~/WispWire/Captures/` под именами вида
`capture_YYYY-MM-DD_HH-MM-SS.pcapng`. Если такое имя уже занято, WispWire
добавляет суффикс `-2`, `-3` и далее, не перезаписывая существующий файл.

Live-захват требует ручной проверки на реальном доступном интерфейсе:
автоматические тесты не подтверждают работу `dumpcap`, права доступа и
появление реальных пакетов. Для приёмки нужно проверить новые пакеты, фильтр,
`W`, переход `S` в файловый TUI и отдельный выход по `Q`.

## Релиз

Публичный релиз создаётся только из чистого `main`. В `main` не должны попадать
локальные каталоги агентов, IDE-настройки, рабочие дампы и другие служебные
файлы. Перед тегом проверьте состав индекса:

```bash
git status --short --branch
git ls-files | rg '(^|/)(\.claude|\.codex|\.cursor|\.gemini|\.vscode|\.codegraph|\.mcp\.json|GEMINI\.md|.*\.pcap|.*\.pcapng)'
```

Если `rg` не нашёл совпадений и вышел с кодом 1, это ожидаемый чистый результат.

Порядок релиза:

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src
.venv/bin/wispwire doctor
.venv/bin/python -m hatchling build -t sdist -t wheel
shasum -a 256 dist/wispwire-0.1.1.tar.gz dist/wispwire-0.1.1-py3-none-any.whl
git tag v0.1.1
git push origin main v0.1.1
```

После появления GitHub Release нужно сверить SHA-256 `wispwire-0.1.1.tar.gz`
с `SHA256SUMS.txt` и использовать этот SHA в Homebrew formula. Formula должна
ставить `wireshark` и Python-зависимости автоматически. `wireshark-chmodbpf`
остаётся отдельной macOS cask-зависимостью уровня прав захвата: Homebrew formula
не может корректно объявить cask как dependency.
