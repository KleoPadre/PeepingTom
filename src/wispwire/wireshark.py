"""Безопасное обнаружение утилит Wireshark."""

import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

VERSION_PATTERN = re.compile(r"([0-9]+(?:\.[0-9]+)+)")


@dataclass(frozen=True)
class ToolStatus:
    """Результат проверки доступности внешней утилиты."""

    name: str
    path: Path | None
    version: str | None
    error: str | None


def inspect_tool(
    name: str,
    which: Callable[[str], str | None] = shutil.which,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> ToolStatus:
    """Проверить доступность утилиты и определить её версию без исключений."""
    tool_path = which(name)
    if tool_path is None:
        return ToolStatus(name, None, None, "утилита не найдена в PATH")

    path = Path(tool_path)
    try:
        result = run(
            [tool_path, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return ToolStatus(name, path, None, "превышено время ожидания ответа утилиты")
    except OSError as error:
        return ToolStatus(name, path, None, f"не удалось запустить утилиту: {error}")

    if result.returncode != 0:
        return ToolStatus(
            name,
            path,
            None,
            f"утилита завершилась с кодом {result.returncode}",
        )

    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    version_match = VERSION_PATTERN.search(first_line)
    if version_match is None:
        return ToolStatus(name, path, None, "не удалось распознать версию утилиты")

    return ToolStatus(name, path, version_match.group(1), None)
