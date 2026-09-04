"""Источник пакетов готового файла для TUI."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from wispwire.index import IndexedPacket, PacketIndex, PacketRecord
from wispwire.packets import PacketSummary
from wispwire.sessions import SessionStorage
from wispwire.tshark import TsharkReadError, iter_packet_summaries


@dataclass(frozen=True)
class PacketQuery:
    """Запрос к файловому источнику пакетов."""

    display_filter: str = ""
    info_query: str = ""
    limit: int = 1000


@dataclass(frozen=True)
class PacketQueryResult:
    """Результат фильтрации пакетов для TUI."""

    packets: tuple[PacketSummary, ...]
    error: str | None = None


class FilePacketSource:
    """Читает готовый захват и держит временный индекс сводок."""

    def __init__(
        self,
        capture_path: Path,
        tshark_path: Path,
        storage: SessionStorage | None = None,
        iter_summaries: Callable[..., Iterator[PacketSummary]] = iter_packet_summaries,
    ) -> None:
        self._capture_path = capture_path
        self._tshark_path = tshark_path
        self._storage = storage or SessionStorage()
        self._iter_summaries = iter_summaries
        self._session = self._storage.create_session()
        self._index = PacketIndex(self._session.path / "packets.sqlite3")
        self._session = self._storage.register_file(
            self._session, self._session.path / "packets.sqlite3"
        )
        self._loaded_packets: dict[int, PacketSummary] = {}
        self._closed = False

    @property
    def session_path(self) -> Path:
        """Путь временной сессии для тестов и диагностики."""
        return self._session.path

    def load(self, limit: int) -> tuple[PacketSummary, ...]:
        """Прочитать начальные сводки и заполнить индекс."""
        if limit < 1:
            raise ValueError("Размер страницы должен быть положительным")

        packets = tuple(
            self._iter_summaries(
                self._capture_path,
                self._tshark_path,
                limit,
                display_filter=None,
            )
        )
        self._loaded_packets = {packet.number: packet for packet in packets}
        self._index.append(_records_from_packets(packets))
        return packets

    def query(self, query: PacketQuery) -> PacketQueryResult:
        """Вернуть пакеты, подходящие под display filter и поиск по Info."""
        if query.limit < 1:
            raise ValueError("Размер страницы должен быть положительным")

        display_filter = query.display_filter.strip()
        info_query = query.info_query.strip()

        info_numbers: set[int] | None = None
        if info_query:
            info_packets = self._index.search_info(
                info_query, limit=len(self._loaded_packets) or 1
            )
            info_numbers = {packet.global_number for packet in info_packets.items}

        if display_filter:
            try:
                display_packets = tuple(
                    self._iter_summaries(
                        self._capture_path,
                        self._tshark_path,
                        query.limit,
                        display_filter=display_filter,
                    )
                )
            except TsharkReadError as error:
                return PacketQueryResult((), str(error))
            return PacketQueryResult(
                _intersect_packets(display_packets, info_numbers, query.limit),
                None,
            )

        if info_numbers is not None:
            indexed_packets = self._index.search_info(info_query, limit=query.limit)
            return PacketQueryResult(
                tuple(
                    _summary_from_indexed(packet) for packet in indexed_packets.items
                ),
                None,
            )

        return PacketQueryResult(
            tuple(self._loaded_packets.values())[: query.limit], None
        )

    def close(self) -> None:
        """Закрыть индекс и удалить временную сессию."""
        if self._closed:
            return
        self._index.close()
        self._storage.close_session(self._session)
        self._closed = True


def _records_from_packets(
    packets: tuple[PacketSummary, ...],
) -> tuple[PacketRecord, ...]:
    return tuple(
        PacketRecord(
            global_number=packet.number,
            segment_id="source-file",
            segment_frame_number=packet.number,
            captured_at=None,
            relative_time=packet.relative_time,
            source=packet.source,
            destination=packet.destination,
            protocol=packet.protocol,
            length=packet.length,
            info=packet.info,
        )
        for packet in packets
    )


def _summary_from_indexed(packet: IndexedPacket) -> PacketSummary:
    return PacketSummary(
        number=packet.global_number,
        relative_time=packet.relative_time,
        source=packet.source,
        destination=packet.destination,
        protocol=packet.protocol,
        length=packet.length,
        info=packet.info,
    )


def _intersect_packets(
    packets: tuple[PacketSummary, ...],
    allowed_numbers: set[int] | None,
    limit: int,
) -> tuple[PacketSummary, ...]:
    if allowed_numbers is None:
        return packets[:limit]
    return tuple(packet for packet in packets if packet.number in allowed_numbers)[
        :limit
    ]
