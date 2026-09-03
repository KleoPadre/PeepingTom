"""Общие helpers для отображения пакетов в TUI."""

from rich.text import Text
from textual.widgets import DataTable

from wispwire.packets import PacketDetails, PacketSummary


def packet_row_values(packet: PacketSummary, wide: bool) -> tuple[Text, ...]:
    """Вернуть literal-Rich значения строки таблицы."""

    values = (
        Text(str(packet.number)),
        Text(packet.relative_time),
        Text(packet.source),
        Text(packet.destination),
        Text(packet.protocol),
        Text(str(packet.length)),
        Text(packet.info),
    )
    if wide:
        return values
    return values[0], values[2], values[4], values[6]


def rebuild_packet_table(
    table: DataTable, packets: tuple[PacketSummary, ...], wide: bool
) -> None:
    """Перестроить таблицу, сохраняя выбранную строку в пределах выдачи."""

    selected_row = table.cursor_row
    table.clear(columns=True)
    if wide:
        table.add_columns(
            "No.",
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Length",
            "Info",
        )
    else:
        table.add_columns("No.", "Source", "Protocol", "Info")
    for packet in packets:
        table.add_row(*packet_row_values(packet, wide))
    if packets:
        table.move_cursor(row=min(selected_row, len(packets) - 1), column=0)


def render_packet_details(packet: PacketSummary, details: PacketDetails) -> Text:
    """Собрать literal-Rich текст подробностей пакета."""

    return Text(
        "\n".join(
            (
                f"No.: {packet.number}",
                f"Time: {packet.relative_time}",
                f"Source: {packet.source}",
                f"Destination: {packet.destination}",
                f"Protocol: {packet.protocol}",
                f"Length: {packet.length}",
                f"Info: {packet.info}",
                "",
                "Дерево протоколов:",
                details.protocol_tree,
                "",
                "Hex/ASCII:",
                details.hex_ascii,
            )
        )
    )
