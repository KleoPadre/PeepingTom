import json
import os
import sys
import uuid
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


def test_cleanup_removes_only_valid_orphan(tmp_path: Path) -> None:
    storage = SessionStorage(
        cache_root=tmp_path, pid=123, is_pid_alive=lambda _pid: False
    )
    session = storage.create_session()

    assert storage.cleanup_orphaned_sessions() == (session.path,)
    assert not session.path.exists()


def test_cleanup_removes_registered_files_from_valid_orphan(tmp_path: Path) -> None:
    storage = SessionStorage(
        cache_root=tmp_path, pid=123, is_pid_alive=lambda _pid: False
    )
    session = storage.create_session()
    payload = session.path / "segments" / "part-0001.pcapng"
    payload.parent.mkdir()
    payload.write_bytes(b"pcapng")
    storage.register_file(session, payload)

    assert storage.cleanup_orphaned_sessions() == (session.path,)
    assert not payload.exists()
    assert not session.path.exists()


def test_cleanup_skips_session_with_live_pid(tmp_path: Path) -> None:
    storage = SessionStorage(
        cache_root=tmp_path, pid=123, is_pid_alive=lambda _pid: True
    )
    session = storage.create_session()

    assert storage.cleanup_orphaned_sessions() == ()
    assert session.path.is_dir()


def test_cleanup_skips_session_containing_symbolic_link(tmp_path: Path) -> None:
    external = tmp_path / "external.txt"
    external.write_text("не удалять", encoding="utf-8")
    storage = SessionStorage(
        cache_root=tmp_path, pid=123, is_pid_alive=lambda _pid: False
    )
    session = storage.create_session()
    (session.path / "linked.txt").symlink_to(external)

    assert storage.cleanup_orphaned_sessions() == ()
    assert session.path.is_dir()
    assert (session.path / "manifest.json").is_file()
    assert external.read_text(encoding="utf-8") == "не удалять"


def test_close_session_does_not_follow_replacement_before_unlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    storage = SessionStorage(cache_root=tmp_path / "sessions", pid=123)
    session = storage.create_session()
    moved_session = tmp_path / "moved-session"
    external = tmp_path / "external"
    external.mkdir()
    external_manifest = external / "manifest.json"
    external_manifest.write_text("не удалять", encoding="utf-8")
    real_unlink = os.unlink
    replaced = False

    def replace_session_then_unlink(
        path: str | bytes | int, *, dir_fd: int | None = None
    ) -> None:
        nonlocal replaced
        if not replaced:
            replaced = True
            session.path.rename(moved_session)
            session.path.symlink_to(external, target_is_directory=True)
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", replace_session_then_unlink)

    assert storage.close_session(session) is False
    assert replaced is True
    assert external_manifest.read_text(encoding="utf-8") == "не удалять"
    assert (moved_session / "manifest.json").exists() is False


def test_close_session_does_not_follow_replaced_subdirectory_before_unlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    storage = SessionStorage(cache_root=tmp_path / "sessions", pid=123)
    session = storage.create_session()
    payload = session.path / "segments" / "part-0001.pcapng"
    payload.parent.mkdir()
    payload.write_bytes("временный файл".encode())
    session = storage.register_file(session, payload)
    moved_segments = session.path / "moved-segments"
    external = tmp_path / "external"
    external.mkdir()
    external_payload = external / payload.name
    external_payload.write_bytes("не удалять".encode())
    real_unlink = os.unlink
    replaced = False

    def replace_subdirectory_then_unlink(
        path: str | bytes | int, *, dir_fd: int | None = None
    ) -> None:
        nonlocal replaced
        path_name = "" if isinstance(path, int) else Path(os.fsdecode(path)).name
        if not replaced and path_name == payload.name:
            replaced = True
            payload.parent.rename(moved_segments)
            payload.parent.symlink_to(external, target_is_directory=True)
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", replace_subdirectory_then_unlink)

    assert storage.close_session(session) is False
    assert replaced is True
    assert external_payload.read_bytes() == "не удалять".encode()
    assert (moved_segments / payload.name).exists() is False


def test_cleanup_rejects_symlink_in_intermediate_cache_root_component(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-parent"
    cache_root = real_parent / "sessions"
    cache_root.mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    storage = SessionStorage(
        cache_root=alias / "sessions",
        pid=123,
        is_pid_alive=lambda _pid: False,
    )
    session = storage.create_session()

    assert storage.cleanup_orphaned_sessions() == ()
    assert session.path.is_dir()
    assert (cache_root / session.path.name / "manifest.json").is_file()


def test_cleanup_returns_empty_and_preserves_session_on_unlink_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    storage = SessionStorage(
        cache_root=tmp_path, pid=123, is_pid_alive=lambda _pid: False
    )
    session = storage.create_session()

    def fail_unlink(_path: str | bytes | int, *, dir_fd: int | None = None) -> None:
        del dir_fd
        raise OSError("ошибка удаления")

    monkeypatch.setattr(os, "unlink", fail_unlink)

    assert storage.cleanup_orphaned_sessions() == ()
    assert session.path.is_dir()
    assert (session.path / "manifest.json").is_file()


def test_cleanup_returns_empty_and_leaves_directory_on_rmdir_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    storage = SessionStorage(
        cache_root=tmp_path, pid=123, is_pid_alive=lambda _pid: False
    )
    session = storage.create_session()
    real_rmdir = os.rmdir

    def fail_session_rmdir(path: str | bytes, *, dir_fd: int | None = None) -> None:
        if Path(os.fsdecode(path)).name == session.path.name:
            raise OSError("ошибка удаления каталога")
        real_rmdir(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "rmdir", fail_session_rmdir)

    assert storage.cleanup_orphaned_sessions() == ()
    assert session.path.is_dir()
    assert (session.path / "manifest.json").exists() is False


def test_cleanup_skips_dangerous_candidates_and_preserves_external_file(
    tmp_path: Path,
) -> None:
    external = tmp_path / "external.txt"
    external.write_text("не удалять", encoding="utf-8")
    storage = SessionStorage(
        cache_root=tmp_path, pid=123, is_pid_alive=lambda _pid: False
    )
    invalid_uuid = tmp_path / "not-a-uuid"
    invalid_uuid.mkdir()
    malformed = tmp_path / str(uuid.uuid4())
    malformed.mkdir()
    (malformed / "manifest.json").write_text("{", encoding="utf-8")
    traversal = tmp_path / str(uuid.uuid4())
    traversal.mkdir()
    (traversal / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "session_id": traversal.name,
                "pid": 123,
                "started_at": "2026-09-01T00:00:00+00:00",
                "owned_files": ["../external.txt"],
            }
        ),
        encoding="utf-8",
    )
    linked = tmp_path / str(uuid.uuid4())
    linked.symlink_to(external)

    assert storage.cleanup_orphaned_sessions() == ()
    assert external.read_text(encoding="utf-8") == "не удалять"
    assert invalid_uuid.exists()
    assert malformed.exists()
    assert traversal.exists()
    assert linked.is_symlink()


def test_close_session_removes_own_valid_session(tmp_path: Path) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123)
    session = storage.create_session()

    assert storage.close_session(session) is True
    assert not session.path.exists()


def test_close_session_rejects_substituted_manifest_and_preserves_external_file(
    tmp_path: Path,
) -> None:
    storage = SessionStorage(cache_root=tmp_path, pid=123)
    session = storage.create_session()
    external = tmp_path / "external.txt"
    external.write_text("не удалять", encoding="utf-8")
    (session.path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "session_id": str(uuid.uuid4()),
                "pid": 123,
                "started_at": "2026-09-01T00:00:00+00:00",
                "owned_files": ["../external.txt"],
            }
        ),
        encoding="utf-8",
    )

    assert storage.close_session(session) is False
    assert session.path.is_dir()
    assert external.read_text(encoding="utf-8") == "не удалять"
