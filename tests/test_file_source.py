from collections.abc import Iterator
from pathlib import Path

import pytest

from wispwire.file_source import FilePacketSource, PacketQuery, PacketQueryResult
from wispwire.packets import PacketSummary
from wispwire.sessions import SessionStorage
from wispwire.tshark import TsharkReadError


def packet(
    number: int,
    protocol: str = "DNS",
    info: str = "Запрос",
) -> PacketSummary:
    return PacketSummary(
        number=number,
        relative_time="0.000000",
        source="192.0.2.1",
        destination="192.0.2.53",
        protocol=protocol,
        length=74,
        info=info,
    )


def test_file_packet_source_load_indexes_initial_packets(tmp_path: Path) -> None:
    packets = (
        packet(number=1, info="Первый запрос"),
        packet(number=2, info="Ответ telegram"),
    )
    source = FilePacketSource(
        tmp_path / "capture.pcapng",
        Path("tshark"),
        storage=SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=lambda *_args, **_kwargs: iter(packets),
    )

    try:
        assert source.load(limit=10) == packets
        assert source.query(PacketQuery(info_query="telegram", limit=10)).packets == (
            packets[1],
        )
    finally:
        source.close()


def test_file_packet_source_intersects_display_filter_and_info_query(
    tmp_path: Path,
) -> None:
    all_packets = (
        packet(number=1, protocol="DNS", info="telegram query"),
        packet(number=2, protocol="TCP", info="telegram tls"),
        packet(number=3, protocol="DNS", info="example query"),
    )
    filtered_packets = (all_packets[0], all_packets[2])
    calls: list[str | None] = []

    def iter_summaries(
        _capture: Path,
        _tshark: Path,
        _limit: int,
        display_filter: str | None = None,
        **_kwargs: object,
    ) -> Iterator[PacketSummary]:
        calls.append(display_filter)
        return iter(filtered_packets if display_filter == "dns" else all_packets)

    source = FilePacketSource(
        tmp_path / "capture.pcapng",
        Path("tshark"),
        storage=SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=iter_summaries,
    )
    try:
        source.load(limit=10)

        result = source.query(
            PacketQuery(display_filter="dns", info_query="telegram", limit=10)
        )

        assert result == PacketQueryResult((all_packets[0],), None)
        assert calls == [None, "dns"]
    finally:
        source.close()


def test_file_packet_source_returns_filter_error_without_losing_index(
    tmp_path: Path,
) -> None:
    packets = (packet(number=1, info="telegram"),)

    def iter_summaries(
        _capture: Path,
        _tshark: Path,
        _limit: int,
        display_filter: str | None = None,
        **_kwargs: object,
    ) -> Iterator[PacketSummary]:
        if display_filter:
            raise TsharkReadError("Синтаксическая ошибка display filter")
        return iter(packets)

    source = FilePacketSource(
        tmp_path / "capture.pcapng",
        Path("tshark"),
        storage=SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=iter_summaries,
    )
    try:
        source.load(limit=10)

        result = source.query(PacketQuery(display_filter="udp &&", limit=10))

        assert result == PacketQueryResult((), "Синтаксическая ошибка display filter")
        assert (
            source.query(PacketQuery(info_query="telegram", limit=10)).packets
            == packets
        )
    finally:
        source.close()


def test_file_packet_source_close_removes_temporary_session(tmp_path: Path) -> None:
    packets = (packet(number=1),)
    source = FilePacketSource(
        tmp_path / "capture.pcapng",
        Path("tshark"),
        storage=SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=lambda *_args, **_kwargs: iter(packets),
    )
    source.load(limit=10)
    session_path = source.session_path

    assert session_path.exists()

    source.close()

    assert not session_path.exists()


def test_file_packet_source_rejects_non_positive_query_limit(tmp_path: Path) -> None:
    source = FilePacketSource(
        tmp_path / "capture.pcapng",
        Path("tshark"),
        storage=SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=lambda *_args, **_kwargs: iter(()),
    )
    try:
        with pytest.raises(ValueError, match="Размер страницы"):
            source.query(PacketQuery(limit=0))
    finally:
        source.close()
