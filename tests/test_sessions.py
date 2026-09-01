import sys
from pathlib import Path

import pytest

from wispwire.sessions import (
    Session,
    SessionManifest,
    SessionSafetyError,
    SessionStorage,
)


def test_create_session_writes_valid_manifest(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123)

    session = storage.create_session()

    assert session.path.parent == tmp_path
    assert session.manifest.session_id == session.path.name
    assert (session.path / "manifest.json").is_file()


def test_default_cache_root_uses_xdg_cache_home_on_linux(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))

    assert SessionStorage.default_cache_root() == tmp_path / "wispwire" / "sessions"


def test_register_file_updates_manifest_and_counts_regular_file(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123)
    session = storage.create_session()
    payload = session.path / "segments" / "part-0001.pcapng"
    payload.parent.mkdir()
    payload.write_bytes(b"abc")

    updated = storage.register_file(session, payload)

    assert updated.manifest.owned_files == ("segments/part-0001.pcapng",)
    assert storage.session_size(updated) >= 3


def test_register_file_rejects_session_without_canonical_uuid(tmp_path: Path) -> None:
    session_path = tmp_path / "not-a-uuid"
    session_path.mkdir()
    session = Session(
        path=session_path,
        manifest=SessionManifest(1, "not-a-uuid", 123, "now", ()),
    )
    payload = session_path / "payload.pcapng"
    payload.write_bytes(b"abc")

    with pytest.raises(SessionSafetyError):
        SessionStorage(cache_root=tmp_path, pid=123).register_file(session, payload)


def test_register_file_rejects_path_outside_session(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123)
    session = storage.create_session()
    payload = tmp_path / "outside.pcapng"
    payload.write_bytes(b"abc")

    with pytest.raises(SessionSafetyError):
        storage.register_file(session, payload)


def test_register_file_rejects_terminal_symlink(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123)
    session = storage.create_session()
    target = tmp_path / "outside.pcapng"
    target.write_bytes(b"abc")
    link = session.path / "linked.pcapng"
    link.symlink_to(target)

    with pytest.raises(SessionSafetyError):
        storage.register_file(session, link)


def test_register_file_rejects_intermediate_symlink(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123)
    session = storage.create_session()
    actual = session.path / "actual"
    actual.mkdir()
    payload = actual / "data.pcapng"
    payload.write_bytes(b"abc")
    link = session.path / "linked"
    link.symlink_to(actual, target_is_directory=True)

    with pytest.raises(SessionSafetyError):
        storage.register_file(session, link / "data.pcapng")


def test_session_size_rejects_symbolic_link(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123)
    session = storage.create_session()
    target = tmp_path / "outside.pcapng"
    target.write_bytes(b"abc")
    (session.path / "linked.pcapng").symlink_to(target)

    with pytest.raises(SessionSafetyError):
        storage.session_size(session)
