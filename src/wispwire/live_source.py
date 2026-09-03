"""Источник пакетов подтверждённых сегментов live-захвата."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path

from wispwire.file_source import PacketQuery, PacketQueryResult
from wispwire.index import PacketIndex, PacketRecord
from wispwire.packets import PacketDetails, PacketSummary
from wispwire.sessions import Session, SessionStorage
from wispwire.tshark import TsharkReadError, iter_packet_summaries, read_packet_details


@dataclass(frozen=True)
class LivePacket:
    """Пакет с глобальным номером и исходным кадром сегмента."""

    summary: PacketSummary
    segment_path: Path
    frame_number: int


class LivePacketSource:
    """Индексирует только уже подтверждённые CaptureSession сегменты."""

    def __init__(
        self,
        tshark_path: Path,
        storage: SessionStorage | None = None,
        *,
        limit: int = 1000,
        iter_summaries: Callable[..., Iterator[PacketSummary]] = iter_packet_summaries,
        read_details: Callable[..., PacketDetails] = read_packet_details,
    ) -> None:
        if limit < 1:
            raise ValueError("Размер страницы должен быть положительным")
        self._tshark_path = tshark_path
        self._storage = storage or SessionStorage()
        self._limit = limit
        self._iter_summaries = iter_summaries
        self._read_details = read_details
        self._session, self._index = self._create_index()
        self._packets: dict[int, LivePacket] = {}
        self._seen_segments: set[Path] = set()
        self._next_number = 1
        self._closed = False

    @property
    def session_path(self) -> Path:
        """Возвращает путь собственной временной сессии."""
        return self._session.path

    @property
    def packet_count(self) -> int:
        """Возвращает количество пакетов с глобальными номерами."""
        return len(self._packets)

    def ingest(self, segments: tuple[Path, ...]) -> tuple[PacketSummary, ...]:
        """Добавляет ранее не обработанные подтверждённые сегменты."""
        added: list[PacketSummary] = []
        for segment in segments:
            if segment in self._seen_segments:
                continue
            for local in self._iter_summaries(segment, self._tshark_path, self._limit):
                global_packet = replace(local, number=self._next_number)
                self._packets[self._next_number] = LivePacket(
                    global_packet, segment, local.number
                )
                self._next_number += 1
                added.append(global_packet)
            self._seen_segments.add(segment)
        self._index.append(_records_from_packets(tuple(added), self._packets))
        return tuple(added)

    def query(self, query: PacketQuery) -> PacketQueryResult:
        """Возвращает пересечение display filter и поиска по полю Info."""
        if query.limit < 1:
            raise ValueError("Размер страницы должен быть положительным")

        display_filter = query.display_filter
        has_display_filter = bool(display_filter.strip())
        info_query = query.info_query.strip()
        info_numbers = self._info_numbers(info_query)

        if has_display_filter:
            try:
                packets = self._display_filtered_packets(display_filter)
            except TsharkReadError as error:
                return PacketQueryResult((), str(error))
            return PacketQueryResult(
                _intersect_packets(packets, info_numbers, query.limit), None
            )

        packets = tuple(item.summary for item in self._packets.values())
        return PacketQueryResult(
            _intersect_packets(packets, info_numbers, query.limit), None
        )

    def read_details(self, global_number: int) -> PacketDetails:
        """Читает детали по локальному номеру кадра в исходном сегменте."""
        packet = self._packets[global_number]
        return self._read_details(
            packet.segment_path, self._tshark_path, packet.frame_number
        )

    def reset(self) -> None:
        """Очищает состояние после успешного перезапуска CaptureSession."""
        if self._closed:
            return
        self._index.close()
        self._storage.close_session(self._session)
        self._session, self._index = self._create_index()
        self._packets.clear()
        self._seen_segments.clear()
        self._next_number = 1

    def close(self) -> None:
        """Закрывает индекс до закрытия только собственной временной сессии."""
        if self._closed:
            return
        self._index.close()
        self._storage.close_session(self._session)
        self._closed = True

    def _create_index(self) -> tuple[Session, PacketIndex]:
        session = self._storage.create_session()
        index_path = session.path / "packets.sqlite3"
        index = PacketIndex(index_path)
        session = self._storage.register_file(session, index_path)
        return session, index

    def _info_numbers(self, query: str) -> set[int] | None:
        if not query:
            return None
        page = self._index.search_info(query, limit=self.packet_count or 1)
        return {packet.global_number for packet in page.items}

    def _display_filtered_packets(
        self, display_filter: str
    ) -> tuple[PacketSummary, ...]:
        matched: list[PacketSummary] = []
        for segment in self._seen_segments:
            for packet in self._iter_summaries(
                segment, self._tshark_path, self._limit, display_filter=display_filter
            ):
                live_packet = next(
                    (
                        item
                        for item in self._packets.values()
                        if item.segment_path == segment
                        and item.frame_number == packet.number
                    ),
                    None,
                )
                if live_packet is not None:
                    matched.append(live_packet.summary)
        return tuple(sorted(matched, key=lambda packet: packet.number))


def _records_from_packets(
    packets: tuple[PacketSummary, ...], live_packets: dict[int, LivePacket]
) -> tuple[PacketRecord, ...]:
    return tuple(
        PacketRecord(
            global_number=packet.number,
            segment_id=str(live_packets[packet.number].segment_path),
            segment_frame_number=live_packets[packet.number].frame_number,
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


def _intersect_packets(
    packets: tuple[PacketSummary, ...], allowed_numbers: set[int] | None, limit: int
) -> tuple[PacketSummary, ...]:
    if allowed_numbers is None:
        return packets[:limit]
    return tuple(packet for packet in packets if packet.number in allowed_numbers)[
        :limit
    ]
