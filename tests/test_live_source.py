from collections.abc import Iterator
from pathlib import Path

from wispwire.file_source import PacketQuery, PacketQueryResult
from wispwire.live_source import LivePacketSource
from wispwire.packets import PacketDetails, PacketSummary
from wispwire.sessions import SessionStorage
from wispwire.tshark import TsharkReadError


def packet(number: int, info: str = "Запрос") -> PacketSummary:
    return PacketSummary(number, "0.000000", "192.0.2.1", "192.0.2.53", "DNS", 74, info)


def test_live_source_keeps_segment_local_frame_for_details(tmp_path: Path) -> None:
    first, second = tmp_path / "one.pcapng", tmp_path / "two.pcapng"
    source = LivePacketSource(
        Path("tshark"),
        SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=lambda path, *_args, **_kwargs: iter(
            [packet(1, info=path.name)]
        ),
        read_details=lambda path, _tshark, number: PacketDetails(
            f"{path.name}:{number}", ""
        ),
    )
    try:
        assert [item.number for item in source.ingest((first, second))] == [1, 2]
        assert source.read_details(2).protocol_tree == "two.pcapng:1"
    finally:
        source.close()


def test_live_source_ignores_duplicate_segment(tmp_path: Path) -> None:
    segment = tmp_path / "one.pcapng"
    source = LivePacketSource(
        Path("tshark"),
        SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=lambda *_args, **_kwargs: iter([packet(1)]),
    )
    try:
        assert source.ingest((segment,)) == (packet(1),)
        assert source.ingest((segment,)) == ()
        assert source.packet_count == 1
    finally:
        source.close()


def test_live_source_uses_global_numbers_for_repeated_local_frames(
    tmp_path: Path,
) -> None:
    first, second = tmp_path / "one.pcapng", tmp_path / "two.pcapng"
    source = LivePacketSource(
        Path("tshark"),
        SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=lambda *_args, **_kwargs: iter([packet(1)]),
    )
    try:
        assert [item.number for item in source.ingest((first, second))] == [1, 2]
    finally:
        source.close()


def test_live_source_intersects_display_filter_and_info_search(tmp_path: Path) -> None:
    first, second = tmp_path / "one.pcapng", tmp_path / "two.pcapng"

    def iter_summaries(
        path: Path, _tshark: Path, _limit: int, display_filter: str | None = None
    ) -> Iterator[PacketSummary]:
        if display_filter:
            return iter([packet(1, "telegram")])
        return iter([packet(1, "telegram" if path == first else "other")])

    source = LivePacketSource(
        Path("tshark"),
        SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=iter_summaries,
    )
    try:
        source.ingest((first, second))
        assert source.query(PacketQuery("dns", "TELEGRAM", 10)) == PacketQueryResult(
            (packet(1, "telegram"),), None
        )
    finally:
        source.close()


def test_live_source_passes_display_filter_to_tshark_unchanged(tmp_path: Path) -> None:
    segment = tmp_path / "one.pcapng"
    filters: list[str | None] = []

    def iter_summaries(
        _path: Path, _tshark: Path, _limit: int, display_filter: str | None = None
    ) -> Iterator[PacketSummary]:
        filters.append(display_filter)
        return iter([packet(1)])

    source = LivePacketSource(
        Path("tshark"),
        SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=iter_summaries,
    )
    try:
        source.ingest((segment,))

        source.query(PacketQuery(display_filter="  dns  ", limit=10))

        assert filters == [None, "  dns  "]
    finally:
        source.close()


def test_live_source_uses_index_for_whitespace_only_display_filter(
    tmp_path: Path,
) -> None:
    segment = tmp_path / "one.pcapng"
    filters: list[str | None] = []

    def iter_summaries(
        _path: Path, _tshark: Path, _limit: int, display_filter: str | None = None
    ) -> Iterator[PacketSummary]:
        filters.append(display_filter)
        return iter([packet(1)])

    source = LivePacketSource(
        Path("tshark"),
        SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=iter_summaries,
    )
    try:
        source.ingest((segment,))

        result = source.query(PacketQuery(display_filter="   ", limit=10))

        assert result == PacketQueryResult((packet(1),), None)
        assert filters == [None]
    finally:
        source.close()


def test_live_source_keeps_index_after_display_filter_error(tmp_path: Path) -> None:
    segment = tmp_path / "one.pcapng"

    def iter_summaries(
        *_args: object, display_filter: str | None = None, **_kwargs: object
    ) -> Iterator[PacketSummary]:
        if display_filter:
            raise TsharkReadError("Синтаксическая ошибка display filter")
        return iter([packet(1, "telegram")])

    source = LivePacketSource(
        Path("tshark"),
        SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=iter_summaries,
    )
    try:
        source.ingest((segment,))
        assert source.query(PacketQuery("udp &&", limit=10)) == PacketQueryResult(
            (), "Синтаксическая ошибка display filter"
        )
        assert source.query(PacketQuery(info_query="telegram", limit=10)).packets == (
            packet(1, "telegram"),
        )
    finally:
        source.close()


def test_live_source_close_removes_only_its_temporary_session(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path / "sessions", pid=123)
    other = storage.create_session()
    source = LivePacketSource(Path("tshark"), storage)
    session_path = source.session_path

    source.close()

    assert not session_path.exists()
    assert other.path.exists()
