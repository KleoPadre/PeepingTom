"""Безопасное хранилище временных сессий WispWire."""

from __future__ import annotations

import json
import os
import sys
import uuid
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

    def __init__(self, cache_root: Path | None = None, pid: int | None = None) -> None:
        self.cache_root = (
            Path(cache_root) if cache_root is not None else self.default_cache_root()
        )
        self.pid = os.getpid() if pid is None else pid

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

    def _validate_session_path(self, session: Session) -> Path:
        session_path = Path(session.path)
        if session_path.name != session.manifest.session_id:
            raise SessionSafetyError("имя сессии не совпадает с manifest")
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
