# WispWire

WispWire — терминальная утилита для диагностики сетевого анализа.

## Установка

Создайте виртуальное окружение и установите пакет с зависимостями разработки:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

## Проверки

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src
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
