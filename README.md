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

Проверить наличие `tshark`, `dumpcap`, `mergecap` и доступность live-захвата:

```bash
.venv/bin/wispwire doctor
```

Посмотреть интерфейсы, которые видит `dumpcap`:

```bash
.venv/bin/wispwire interfaces
```

Эти команды только читают сведения об окружении и не требуют `sudo`. Права могут
понадобиться позднее, при запуске live-захвата.

## Открытие готового захвата

Вывести ограниченную сводку пакетов из готового файла можно так:

```bash
.venv/bin/wispwire open ~/Downloads/capture.pcapng
.venv/bin/wispwire open ~/Downloads/capture.pcap --limit 500
```

Пока команда выводит ограниченную таблицу в терминал, не открывает TUI и не
изменяет исходный файл. Фильтры и поиск будут добавлены на следующих этапах.
