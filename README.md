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
