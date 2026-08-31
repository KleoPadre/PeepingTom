from dataclasses import dataclass


@dataclass(frozen=True)
class PacketDetails:
    """Подробности одного пакета для представления дерева и дампа."""

    protocol_tree: str
    hex_ascii: str


@dataclass(frozen=True)
class PacketSummary:
    """Сводка одного пакета для табличного представления."""

    number: int
    relative_time: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str
