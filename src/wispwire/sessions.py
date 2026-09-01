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
        try:
            if not self._is_safe_session_directory(session_path):
                return False
            manifest = self._read_manifest(session_path)
            if (
                manifest is None
                or manifest != session.manifest
                or manifest.pid != self.pid
            ):
                return False
            return self._remove_safe_session(session_path, manifest)
        except OSError:
            return False

    def cleanup_orphaned_sessions(self) -> tuple[Path, ...]:
        """Удаляет подтверждённые сессии, чей процесс-владелец уже завершился."""
        if self.cache_root.is_symlink() or not self.cache_root.is_dir():
            return ()

        removed: list[Path] = []
        try:
            candidates = tuple(self.cache_root.iterdir())
        except OSError:
            return ()
        for candidate in candidates:
            try:
                if not self._is_safe_session_directory(candidate):
                    continue
                manifest = self._read_manifest(candidate)
                if manifest is None or self.is_pid_alive(manifest.pid):
                    continue
                if self._remove_safe_session(candidate, manifest):
                    removed.append(candidate)
            except OSError:
                continue
        return tuple(removed)

    def _is_safe_session_directory(self, candidate: Path) -> bool:
        if self.cache_root.is_symlink() or candidate.is_symlink():
            return False
        if candidate.parent != self.cache_root or not candidate.is_dir():
            return False
        if not self._is_within(self.cache_root, candidate, strict=True):
            return False
        try:
            parsed_id = uuid.UUID(candidate.name)
        except ValueError:
            return False
        return str(parsed_id) == candidate.name

    def _read_manifest(self, session_path: Path) -> SessionManifest | None:
        manifest_path = session_path / "manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            return None
        if not self._is_within(session_path, manifest_path, strict=True):
            return None
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None
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
        if session_id != session_path.name or not self._is_canonical_uuid(session_id):
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
                self._safe_owned_path(session_path, path)
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
        self, session_path: Path, manifest: SessionManifest
    ) -> bool:
        paths = self._collect_removable_paths(session_path, manifest)
        if paths is None:
            return False
        files, directories = paths
        try:
            for path in files:
                path.unlink()
            for path in reversed(directories):
                path.rmdir()
            session_path.rmdir()
        except OSError:
            return False
        return True

    def _collect_removable_paths(
        self, session_path: Path, manifest: SessionManifest
    ) -> tuple[list[Path], list[Path]] | None:
        files: list[Path] = []
        directories: list[Path] = []
        owned_paths = set(manifest.owned_files)

        def collect(directory: Path) -> bool:
            try:
                children = tuple(directory.iterdir())
            except OSError:
                return False
            for child in children:
                if child.is_symlink() or not self._is_within(
                    session_path, child, strict=True
                ):
                    return False
                try:
                    mode = child.lstat().st_mode
                except OSError:
                    return False
                if stat.S_ISREG(mode):
                    relative = child.relative_to(session_path).as_posix()
                    if relative != "manifest.json" and relative not in owned_paths:
                        return False
                    files.append(child)
                elif stat.S_ISDIR(mode):
                    if not collect(child):
                        return False
                    directories.append(child)
                else:
                    return False
            return True

        if not collect(session_path):
            return None
        return files, directories

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

    def _safe_owned_path(self, session_path: Path, value: str) -> None:
        relative = Path(value)
        if relative.is_absolute() or any(
            part in ("", ".", "..") for part in relative.parts
        ):
            raise SessionSafetyError("недопустимый путь в manifest")
        path = session_path / relative
        if not self._is_within(session_path, path, strict=True):
            raise SessionSafetyError("путь manifest выходит за пределы сессии")

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
