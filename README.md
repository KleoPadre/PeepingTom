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
python -m pytest
ruff check src tests
ruff format --check src tests
mypy src
```

