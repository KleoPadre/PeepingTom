"""Общие helpers для UX Wireshark display filter."""

from __future__ import annotations

import re
from bisect import bisect_left


def format_display_filter_error(error: str) -> str:
    """Сжать ошибку TShark и добавить понятную подсказку для частого случая."""

    compact = " ".join(line.strip() for line in error.splitlines() if line.strip())
    lowered = compact.lower()
    if '"tcp" is not a valid protocol' in lowered:
        return "Невалидный display filter. Wireshark ожидает `tcp`, а не `TCP`."
    if '"udp" is not a valid protocol' in lowered:
        return "Невалидный display filter. Wireshark ожидает `udp`, а не `UDP`."
    if "not a valid protocol or protocol field" in lowered:
        return "Невалидный display filter. Проверьте регистр имени протокола или поля."
    if "syntax error" in lowered or "is neither a field nor a protocol name" in lowered:
        return f"Невалидный display filter: {compact}"
    return compact


def filter_suggestions(value: str, fields: tuple[str, ...]) -> tuple[str, ...]:
    """Вернуть ближайшие display-filter поля по текущему токену."""

    if not fields:
        return ()
    match = re.search(r"([A-Za-z_][A-Za-z0-9_.]*)$", value)
    if match is None:
        return ()
    prefix = match.group(1).lower()
    index = bisect_left(fields, prefix)
    suggestions: list[str] = []
    while index < len(fields) and fields[index].startswith(prefix):
        suggestions.append(fields[index])
        if len(suggestions) == 6:
            break
        index += 1
    return tuple(suggestions)


def draft_filter_error(value: str, fields: tuple[str, ...]) -> str | None:
    """Вернуть быструю ошибку для явно неизвестного поля во время ввода."""

    if not fields:
        return None
    match = re.search(r"([A-Za-z_][A-Za-z0-9_.]*)$", value)
    if match is None:
        return None
    token = match.group(1)
    if "." not in token:
        return None
    prefix = token.lower()
    if prefix in fields:
        return None
    if filter_suggestions(token, fields):
        return None
    return f"Неизвестное поле display filter: {token}"
