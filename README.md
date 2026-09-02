# WispWire

WispWire — терминальная утилита для диагностики сетевого анализа.

## Установка

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
```

TUI не изменяет исходный файл: `tshark` читает только сводки и по выбранному
кадру показывает дерево протоколов и hex/ASCII-дамп. Используйте `↑` и `↓` для
выбора пакета, `Tab` для смены фокуса и `Q` для выхода. WispWire не заменяет
Wireshark: поиск и фильтры будут добавлены на следующих этапах.

## Live-захват

Запустить сегментированный live-захват на известном `dumpcap` интерфейсе можно
так:

```bash
.venv/bin/wispwire capture --iface en0
```

Перед стартом команда проверяет `dumpcap`, `mergecap` и выбранный интерфейс.
Она создаёт временную сессию только после этих проверок. Сейчас команда
запускает программный слой захвата; управление им из TUI появится на этапе 7.
