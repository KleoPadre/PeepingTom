import sys
from pathlib import Path

import pytest

from wispwire.sessions import SessionStorage


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
