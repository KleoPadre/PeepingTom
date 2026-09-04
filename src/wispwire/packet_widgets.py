"""Общие helpers для отображения пакетов в TUI."""

from rich.text import Text
from textual.widgets import DataTable

from wispwire.packets import PacketDetails, PacketSummary

_DEFAULT_PROTOCOL_STYLE = "bold white on #303030"
_PROTOCOL_STYLES = {
    "ARP": "bold white on #3a3325",
    "DNS": "bold cyan on #123047",
    "MDNS": "bold white on #303030",
    "NBSS": "bold magenta on #33213f",
    "SMB": "bold magenta on #33213f",
    "SMB2": "bold magenta on #33213f",
    "TCP": "bold #c8b6ff on #2d1f55",
    "TLS": "bold green on #12382d",
    "TLSV1.2": "bold green on #12382d",
    "TLSV1.3": "bold green on #12382d",
    "UDP": "bold #ffd166 on #403518",
    "HTTP": "bold blue on #142d4f",
    "HTTP2": "bold blue on #142d4f",
    "ICMP": "bold red on #421f24",
    "ICMPV6": "bold red on #421f24",
}


def packet_row_values(packet: PacketSummary, wide: bool) -> tuple[Text, ...]:
    """Вернуть literal-Rich значения строки таблицы."""

    values = (
        Text(str(packet.number)),
        Text(packet.relative_time),
        Text(packet.source),
        Text(packet.destination),
        protocol_badge(packet.protocol),
        Text(str(packet.length)),
        Text(packet.info),
    )
    if wide:
        return values
    return values[0], values[2], values[4], values[6]


def protocol_badge(protocol: str) -> Text:
    """Вернуть цветной literal-Rich badge протокола."""

    style = _PROTOCOL_STYLES.get(protocol.upper(), _DEFAULT_PROTOCOL_STYLE)
    return Text(protocol, style=style)


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
