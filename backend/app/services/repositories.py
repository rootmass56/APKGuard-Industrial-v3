"""Small local repositories retained until PostgreSQL/object storage arrive in Phase 2."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger("apkguard.repositories")


class AtomicJsonFile:
    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self, default: Any) -> Any:
        try:
            if not self.path.exists():
                return default
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            log.warning("Could not read JSON store %s: %s", self.path, exc)
            return default

    def write(self, value: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary_name = handle.name
                json.dump(value, handle, indent=2, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.path)
        finally:
            if temporary_name:
                Path(temporary_name).unlink(missing_ok=True)


class CacheRepository:
    def __init__(self, directory: Path, enabled: bool, schema_version: str) -> None:
        self.directory = directory
        self.enabled = enabled
        self.schema_version = schema_version
        if enabled:
            directory.mkdir(parents=True, exist_ok=True)

    def _path(self, sha256: str) -> Path:
        return self.directory / f"{sha256}.schema-{self.schema_version}.json"

    def load(self, sha256: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        value = AtomicJsonFile(self._path(sha256)).read(None)
        if not isinstance(value, dict) or value.get("schema_version") != self.schema_version:
            return None
        return value

    def save(self, sha256: str, result: dict[str, Any]) -> None:
        if self.enabled:
            AtomicJsonFile(self._path(sha256)).write(result)


class HistoryRepository:
    def __init__(self, path: Path, enabled: bool, limit: int) -> None:
        self.store = AtomicJsonFile(path)
        self.enabled = enabled
        self.limit = limit

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        records = self.store.read([])
        if not isinstance(records, list):
            return []
        return [record for record in records[-max(1, limit):] if isinstance(record, dict)]

    def count(self) -> int:
        if not self.enabled:
            return 0
        records = self.store.read([])
        return len(records) if isinstance(records, list) else 0

    def append(self, record: dict[str, Any]) -> None:
        if not self.enabled:
            return
        records = self.store.read([])
        if not isinstance(records, list):
            records = []
        records.append(record)
        self.store.write(records[-self.limit:])
