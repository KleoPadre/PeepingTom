from dataclasses import dataclass


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
