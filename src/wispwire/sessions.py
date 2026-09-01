"""Безопасное хранилище временных сессий WispWire."""

from __future__ import annotations

import json
import os
import stat
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class SessionSafetyError(RuntimeError):
    """Операция затрагивает небезопасный путь или файл."""


@dataclass(frozen=True)
class SessionManifest:
    schema_version: int
    session_id: str
    pid: int
    started_at: str
    owned_files: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "pid": self.pid,
            "started_at": self.started_at,
            "owned_files": list(self.owned_files),
        }


@dataclass(frozen=True)
class Session:
    path: Path
    manifest: SessionManifest


@dataclass(frozen=True)
class _RemovableDirectory:
    name: str
    fd: int
    contents: _RemovableContents


@dataclass(frozen=True)
class _RemovableContents:
    files: tuple[str, ...]
    directories: tuple[_RemovableDirectory, ...]


class SessionStorage:
    """Создаёт сессии внутри выделенного корня cache."""

    def __init__(
        self,
        cache_root: Path | None = None,
        pid: int | None = None,
        is_pid_alive: Callable[[int], bool] | None = None,
    ) -> None:
        self.cache_root = (
            Path(cache_root) if cache_root is not None else self.default_cache_root()
        )
        self.pid = os.getpid() if pid is None else pid
        self.is_pid_alive = is_pid_alive or self._default_is_pid_alive

    @staticmethod
    def default_cache_root() -> Path:
        if sys.platform == "darwin":
            return Path.home() / "Library/Caches/WispWire/sessions"
        if sys.platform == "linux":
            cache_home = os.environ.get("XDG_CACHE_HOME")
            return (
                Path(cache_home) if cache_home else Path.home() / ".cache"
            ) / "wispwire/sessions"
        return Path.home() / ".cache/wispwire/sessions"

    def create_session(self) -> Session:
        self.cache_root.mkdir(parents=True, exist_ok=True)
        while True:
            session_id = str(uuid.uuid4())
            session_path = self.cache_root / session_id
            try:
                session_path.mkdir()
            except FileExistsError:
                continue
            break

        manifest = SessionManifest(
            schema_version=1,
            session_id=session_id,
            pid=self.pid,
            started_at=datetime.now(UTC).isoformat(),
            owned_files=(),
        )
        self._write_manifest(session_path, manifest)
        return Session(path=session_path, manifest=manifest)

    def register_file(self, session: Session, path: Path) -> Session:
        session_path = self._validate_session_path(session)
        file_path = Path(path)
        if file_path.is_symlink() or not file_path.is_file():
            raise SessionSafetyError("зарегистрировать можно только обычный файл")
        relative = self._safe_relative_path(session_path, file_path)
        owned_files = session.manifest.owned_files
        if relative not in owned_files:
            owned_files = (*owned_files, relative)
        manifest = SessionManifest(
            schema_version=session.manifest.schema_version,
            session_id=session.manifest.session_id,
            pid=session.manifest.pid,
            started_at=session.manifest.started_at,
            owned_files=owned_files,
        )
        self._write_manifest(session_path, manifest)
        return Session(path=session_path, manifest=manifest)

    def session_size(self, session: Session) -> int:
        session_path = self._validate_session_path(session)
        size = 0
        for path in session_path.rglob("*"):
            if path.is_symlink():
                raise SessionSafetyError("символьная ссылка запрещена в сессии")
            if not self._is_within(session_path, path):
                raise SessionSafetyError("путь выходит за пределы сессии")
            if path.is_file():
                size += path.stat().st_size
        return size

    def close_session(self, session: Session) -> bool:
        """Удаляет только собственную подтверждённую временную сессию."""
        session_path = Path(session.path)
        if (
            session_path.parent != self.cache_root
            or session_path.name != session.manifest.session_id
            or not self._is_canonical_uuid(session_path.name)
        ):
            return False
        try:
            cache_fd = self._open_cache_root()
        except OSError:
            return False
        try:
            session_fd = self._open_directory(session_path.name, dir_fd=cache_fd)
        except OSError:
            os.close(cache_fd)
            return False
        try:
            manifest = self._read_manifest(session_fd, session_path.name)
            if manifest != session.manifest or manifest.pid != self.pid:
                return False
            return self._remove_safe_session(
                cache_fd, session_path.name, session_fd, manifest
            )
        except OSError:
            return False
        finally:
            os.close(session_fd)
            os.close(cache_fd)

    def cleanup_orphaned_sessions(self) -> tuple[Path, ...]:
        """Удаляет подтверждённые сессии, чей процесс-владелец уже завершился."""
        try:
            cache_fd = self._open_cache_root()
        except OSError:
            return ()

        removed: list[Path] = []
        try:
            candidates = tuple(os.listdir(cache_fd))
        except OSError:
            os.close(cache_fd)
            return ()
        try:
            for session_id in candidates:
                if not self._is_canonical_uuid(session_id):
                    continue
                try:
                    session_fd = self._open_directory(session_id, dir_fd=cache_fd)
                except OSError:
                    continue
                try:
                    manifest = self._read_manifest(session_fd, session_id)
                    if manifest is None or self.is_pid_alive(manifest.pid):
                        continue
                    if self._remove_safe_session(
                        cache_fd, session_id, session_fd, manifest
                    ):
                        removed.append(self.cache_root / session_id)
                except OSError:
                    continue
                finally:
                    os.close(session_fd)
        finally:
            os.close(cache_fd)
        return tuple(removed)

    def _open_cache_root(self) -> int:
        absolute_root = Path(os.path.abspath(self.cache_root))
        current_fd = self._open_directory(os.sep)
        try:
            for component in absolute_root.parts[1:]:
                next_fd = self._open_directory(component, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
        except OSError:
            os.close(current_fd)
            raise
        return current_fd

    @staticmethod
    def _open_directory(path: str, dir_fd: int | None = None) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        flags |= getattr(os, "O_CLOEXEC", 0)
        return os.open(path, flags, dir_fd=dir_fd)

    def _read_manifest(
        self, session_fd: int, expected_session_id: str
    ) -> SessionManifest | None:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            manifest_fd = os.open("manifest.json", flags, dir_fd=session_fd)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(manifest_fd).st_mode):
                return None
            with os.fdopen(manifest_fd, encoding="utf-8") as manifest_file:
                manifest_fd = -1
                payload = json.load(manifest_file)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        finally:
            if manifest_fd != -1:
                os.close(manifest_fd)
        if not isinstance(payload, dict):
            return None
        if set(payload) != {
            "schema_version",
            "session_id",
            "pid",
            "started_at",
            "owned_files",
        }:
            return None

        schema_version = payload["schema_version"]
        session_id = payload["session_id"]
        pid = payload["pid"]
        started_at = payload["started_at"]
        owned_files = payload["owned_files"]
        if (
            type(schema_version) is not int
            or schema_version != 1
            or not isinstance(session_id, str)
            or type(pid) is not int
            or pid <= 0
            or not isinstance(started_at, str)
            or not isinstance(owned_files, list)
            or any(not isinstance(path, str) for path in owned_files)
        ):
            return None
        if session_id != expected_session_id or not self._is_canonical_uuid(session_id):
            return None
        try:
            timestamp = datetime.fromisoformat(started_at)
        except ValueError:
            return None
        if timestamp.tzinfo is None or timestamp.utcoffset() != UTC.utcoffset(
            timestamp
        ):
            return None
        normalized_owned = tuple(owned_files)
        if len(set(normalized_owned)) != len(normalized_owned):
            return None
        try:
            for path in normalized_owned:
                self._validate_owned_path(path)
        except SessionSafetyError:
            return None
        return SessionManifest(
            schema_version=schema_version,
            session_id=session_id,
            pid=pid,
            started_at=started_at,
            owned_files=normalized_owned,
        )

    def _remove_safe_session(
        self,
        cache_fd: int,
        session_id: str,
        session_fd: int,
        manifest: SessionManifest,
    ) -> bool:
        contents = self._collect_removable_contents(
            session_fd, (), set(manifest.owned_files)
        )
        if contents is None:
            return False
        try:
            self._remove_contents(session_fd, contents)
            if not self._is_same_directory(cache_fd, session_id, session_fd):
                return False
            os.rmdir(session_id, dir_fd=cache_fd)
        except OSError:
            return False
        finally:
            self._close_contents(contents)
        return True

    def _collect_removable_contents(
        self,
        directory_fd: int,
        relative_parts: tuple[str, ...],
        owned_paths: set[str],
    ) -> _RemovableContents | None:
        files: list[str] = []
        directories: list[_RemovableDirectory] = []
        try:
            names = sorted(os.listdir(directory_fd))
            for name in names:
                mode = os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode
                relative = "/".join((*relative_parts, name))
                if stat.S_ISREG(mode):
                    if relative != "manifest.json" and relative not in owned_paths:
                        raise SessionSafetyError("обнаружен незарегистрированный файл")
                    files.append(name)
                elif stat.S_ISDIR(mode):
                    child_fd = self._open_directory(name, dir_fd=directory_fd)
                    child_contents = self._collect_removable_contents(
                        child_fd, (*relative_parts, name), owned_paths
                    )
                    if child_contents is None:
                        os.close(child_fd)
                        raise SessionSafetyError("каталог сессии небезопасен")
                    directories.append(
                        _RemovableDirectory(name, child_fd, child_contents)
                    )
                else:
                    raise SessionSafetyError("обнаружен небезопасный объект")
        except (OSError, SessionSafetyError):
            self._close_contents(_RemovableContents((), tuple(directories)))
            return None
        return _RemovableContents(tuple(files), tuple(directories))

    def _remove_contents(self, directory_fd: int, contents: _RemovableContents) -> None:
        for name in contents.files:
            os.unlink(name, dir_fd=directory_fd)
        for directory in reversed(contents.directories):
            self._remove_contents(directory.fd, directory.contents)
            if not self._is_same_directory(directory_fd, directory.name, directory.fd):
                raise OSError("каталог был подменён во время удаления")
            os.rmdir(directory.name, dir_fd=directory_fd)

    @classmethod
    def _close_contents(cls, contents: _RemovableContents) -> None:
        for directory in contents.directories:
            cls._close_contents(directory.contents)
            os.close(directory.fd)

    @staticmethod
    def _is_same_directory(parent_fd: int, name: str, directory_fd: int) -> bool:
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            opened = os.fstat(directory_fd)
        except OSError:
            return False
        return (
            stat.S_ISDIR(current.st_mode)
            and current.st_dev == opened.st_dev
            and current.st_ino == opened.st_ino
        )

    @staticmethod
    def _default_is_pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    @staticmethod
    def _is_canonical_uuid(value: str) -> bool:
        try:
            return str(uuid.UUID(value)) == value
        except ValueError:
            return False

    @staticmethod
    def _validate_owned_path(value: str) -> None:
        relative = Path(value)
        if (
            not relative.parts
            or relative.is_absolute()
            or any(part in ("", ".", "..") for part in relative.parts)
        ):
            raise SessionSafetyError("недопустимый путь в manifest")

    def _validate_session_path(self, session: Session) -> Path:
        session_path = Path(session.path)
        if session_path.name != session.manifest.session_id:
            raise SessionSafetyError("имя сессии не совпадает с manifest")
        try:
            parsed_id = uuid.UUID(session_path.name)
        except ValueError as error:
            raise SessionSafetyError("имя сессии не является UUID") from error
        if str(parsed_id) != session_path.name:
            raise SessionSafetyError("имя сессии не является каноническим UUID")
        if not self._is_within(self.cache_root, session_path, strict=True):
            raise SessionSafetyError("сессия находится вне cache-root")
        if session_path.is_symlink() or not session_path.is_dir():
            raise SessionSafetyError("каталог сессии небезопасен")
        return session_path

    @staticmethod
    def _is_within(root: Path, candidate: Path, strict: bool = False) -> bool:
        try:
            root_resolved = root.resolve()
            candidate_resolved = candidate.resolve()
            if strict and candidate_resolved == root_resolved:
                return False
            candidate_resolved.relative_to(root_resolved)
            candidate.relative_to(root)
        except ValueError:
            return False
        return True

    def _safe_relative_path(self, session_path: Path, path: Path) -> str:
        if not self._is_within(session_path, path, strict=True):
            raise SessionSafetyError("файл находится вне сессии")
        try:
            relative = path.relative_to(session_path)
        except ValueError as error:
            raise SessionSafetyError("файл находится вне сессии") from error
        if any(part in ("", ".", "..") for part in relative.parts):
            raise SessionSafetyError("недопустимый относительный путь")
        current = session_path
        for component in relative.parts:
            current /= component
            if current.is_symlink():
                raise SessionSafetyError("символьная ссылка запрещена в пути")
        return relative.as_posix()

    @staticmethod
    def _write_manifest(session_path: Path, manifest: SessionManifest) -> None:
        temporary = session_path / f".manifest-{uuid.uuid4().hex}.tmp"
        try:
            temporary.write_text(
                json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary.replace(session_path / "manifest.json")
        finally:
            temporary.unlink(missing_ok=True)
