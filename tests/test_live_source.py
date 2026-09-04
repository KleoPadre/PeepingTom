import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from wispwire.file_source import PacketQuery, PacketQueryResult
from wispwire.live_source import LivePacketSource
from wispwire.packets import PacketDetails, PacketSummary
from wispwire.sessions import Session, SessionSafetyError, SessionStorage
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


def test_live_source_rolls_back_segment_when_tshark_fails_after_packet(
    tmp_path: Path,
) -> None:
    segment = tmp_path / "one.pcapng"
    attempts = 0

    def iter_summaries(*_args: object, **_kwargs: object) -> Iterator[PacketSummary]:
        nonlocal attempts
        attempts += 1
        yield packet(1, "первый")
        if attempts == 1:
            raise TsharkReadError("TShark оборвал чтение сегмента")
        yield packet(2, "второй")

    source = LivePacketSource(
        Path("tshark"),
        SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=iter_summaries,
    )
    try:
        with pytest.raises(TsharkReadError, match="оборвал чтение"):
            source.ingest((segment,))

        assert source.packet_count == 0
        assert source.query(PacketQuery(limit=10)).packets == ()

        assert source.ingest((segment,)) == (
            packet(1, "первый"),
            packet(2, "второй"),
        )
        assert source.packet_count == 2
        assert source.query(PacketQuery(info_query="первый", limit=10)).packets == (
            packet(1, "первый"),
        )
        assert source.query(PacketQuery(info_query="второй", limit=10)).packets == (
            packet(2, "второй"),
        )
        assert source.ingest((segment,)) == ()
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


def test_live_source_serializes_access_from_background_threads(
    tmp_path: Path,
) -> None:
    segment = tmp_path / "one.pcapng"
    ingest_started = threading.Event()
    release_ingest = threading.Event()
    query_started = threading.Event()

    def iter_summaries(
        _path: Path, _tshark: Path, _limit: int, display_filter: str | None = None
    ) -> Iterator[PacketSummary]:
        if display_filter is None:
            ingest_started.set()
            assert release_ingest.wait(timeout=1)
        return iter([packet(1)])

    source = LivePacketSource(
        Path("tshark"),
        SessionStorage(cache_root=tmp_path / "sessions", pid=123),
        iter_summaries=iter_summaries,
    )

    def query() -> PacketQueryResult:
        query_started.set()
        return source.query(PacketQuery(display_filter="dns", limit=10))

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            ingest = executor.submit(source.ingest, (segment,))
            assert ingest_started.wait(timeout=1)
            filtered = executor.submit(query)
            assert query_started.wait(timeout=1)
            assert not filtered.done()

            release_ingest.set()
            assert ingest.result(timeout=1) == (packet(1),)
            assert filtered.result(timeout=1) == PacketQueryResult((packet(1),), None)
    finally:
        release_ingest.set()
        source.close()


def test_live_source_close_removes_only_its_temporary_session(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path / "sessions", pid=123)
    other = storage.create_session()
    source = LivePacketSource(Path("tshark"), storage)
    session_path = source.session_path

    source.close()

    assert not session_path.exists()
    assert other.path.exists()


def test_live_source_close_reports_cleanup_failure_and_allows_retry(
    tmp_path: Path,
) -> None:
    storage = SessionStorage(cache_root=tmp_path / "sessions", pid=123)
    source = LivePacketSource(Path("tshark"), storage)
    session_path = source.session_path
    real_close_session = storage.close_session
    attempts = 0

    def close_session(session: Session) -> bool:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return False
        return real_close_session(session)

    storage.close_session = close_session

    with pytest.raises(SessionSafetyError, match="закрыть сессию"):
        source.close()

    assert source.session_path == session_path
    assert session_path.exists()

    source.close()

    assert attempts == 2
    assert not session_path.exists()


def test_live_source_reset_keeps_old_session_and_packets_for_cleanup_retry(
    tmp_path: Path,
) -> None:
    storage = SessionStorage(cache_root=tmp_path / "sessions", pid=123)
    source = LivePacketSource(
        Path("tshark"),
        storage,
        iter_summaries=lambda *_args, **_kwargs: iter([packet(1)]),
    )
    source.ingest((tmp_path / "one.pcapng",))
    old_session_path = source.session_path
    real_close_session = storage.close_session
    attempts = 0

    def close_session(session: Session) -> bool:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return False
        return real_close_session(session)

    storage.close_session = close_session
    try:
        with pytest.raises(SessionSafetyError, match="закрыть сессию"):
            source.reset()

        assert source.session_path == old_session_path
        assert source.packet_count == 1
        assert old_session_path.exists()

        source.reset()

        assert source.session_path != old_session_path
        assert source.packet_count == 0
        assert not old_session_path.exists()
    finally:
        source.close()


def test_live_source_removes_new_session_when_index_registration_fails(
    tmp_path: Path,
) -> None:
    class FailingRegistrationStorage(SessionStorage):
        created_session: Session | None = None

        def create_session(self) -> Session:
            session = super().create_session()
            self.created_session = session
            return session

        def register_file(self, session: Session, path: Path) -> Session:
            raise SessionSafetyError("не удалось зарегистрировать индекс")

    storage = FailingRegistrationStorage(cache_root=tmp_path / "sessions", pid=123)

    with pytest.raises(SessionSafetyError, match="зарегистрировать индекс"):
        LivePacketSource(Path("tshark"), storage)

    assert storage.created_session is not None
    assert not storage.created_session.path.exists()


def test_live_source_reports_index_creation_cleanup_failure(
    tmp_path: Path,
) -> None:
    class FailingCleanupStorage(SessionStorage):
        created_session: Session | None = None

        def create_session(self) -> Session:
            session = super().create_session()
            self.created_session = session
            return session

        def register_file(self, session: Session, path: Path) -> Session:
            raise SessionSafetyError("не удалось зарегистрировать индекс")

        def close_session(self, session: Session) -> bool:
            return False

    storage = FailingCleanupStorage(cache_root=tmp_path / "sessions", pid=123)

    with pytest.raises(SessionSafetyError, match="закрыть сессию live-источника"):
        LivePacketSource(Path("tshark"), storage)

    assert storage.created_session is not None
    assert storage.created_session.path.exists()
