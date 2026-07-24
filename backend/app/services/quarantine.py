"""Content-addressed, non-executable quarantine storage."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.services.upload_service import UploadArtifact

log = logging.getLogger("apkguard.quarantine")


@dataclass(frozen=True, slots=True)
class QuarantinedArtifact:
    original_filename: str
    quarantine_path: Path
    sha256: str
    size_bytes: int
    zip_entry_count: int
    total_uncompressed_bytes: int
    deduplicated: bool


class QuarantineStorage:
    def __init__(self, settings: Settings) -> None:
        self.root = settings.quarantine_dir
        self.root.mkdir(parents=True, exist_ok=True)
        self._restrict_directory(self.root)

    def path_for(self, sha256: str) -> Path:
        if len(sha256) != 64 or any(character not in "0123456789abcdef" for character in sha256.lower()):
            raise ValueError("Invalid SHA-256 value.")
        return self.root / sha256[:2] / sha256[2:4] / f"{sha256}.apk"

    def store(self, artifact: UploadArtifact) -> QuarantinedArtifact:
        destination = self.path_for(artifact.sha256)
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._restrict_directory(destination.parent)
        deduplicated = destination.exists()
        if deduplicated:
            self._verify_existing(destination, artifact.sha256, artifact.size_bytes)
        else:
            temporary_name: str | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=destination.parent,
                    prefix=f".{artifact.sha256}.",
                    suffix=".quarantine",
                    delete=False,
                ) as handle:
                    temporary_name = handle.name
                    with artifact.temporary_path.open("rb") as source:
                        shutil.copyfileobj(source, handle, length=1024 * 1024)
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary_path = Path(temporary_name)
                self._verify_existing(temporary_path, artifact.sha256, artifact.size_bytes)
                temporary_path.chmod(0o600)
                os.replace(temporary_path, destination)
                destination.chmod(0o600)
            finally:
                if temporary_name:
                    Path(temporary_name).unlink(missing_ok=True)

        self._write_metadata(destination, artifact, deduplicated)
        return QuarantinedArtifact(
            original_filename=artifact.original_filename,
            quarantine_path=destination,
            sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,
            zip_entry_count=artifact.zip_entry_count,
            total_uncompressed_bytes=artifact.total_uncompressed_bytes,
            deduplicated=deduplicated,
        )

    @staticmethod
    def _verify_existing(path: Path, expected_sha256: str, expected_size: int) -> None:
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                total += len(chunk)
        if digest.hexdigest() != expected_sha256 or total != expected_size:
            raise AppError(
                "Quarantine integrity verification failed.",
                code=ErrorCode.INTERNAL_ERROR,
                status_code=500,
                details={"expected_size": expected_size, "actual_size": total},
            )

    @staticmethod
    def _restrict_directory(path: Path) -> None:
        try:
            path.chmod(0o700)
        except OSError as exc:
            # Windows ACLs are not represented by POSIX chmod; generated paths and ACL inheritance still apply.
            log.debug("Could not apply POSIX directory mode to %s: %s", path, exc)

    @staticmethod
    def _write_metadata(destination: Path, artifact: UploadArtifact, deduplicated: bool) -> None:
        metadata_path = destination.with_suffix(".metadata.json")
        metadata = {
            "sha256": artifact.sha256,
            "original_filename": artifact.original_filename,
            "size_bytes": artifact.size_bytes,
            "zip_entry_count": artifact.zip_entry_count,
            "total_uncompressed_bytes": artifact.total_uncompressed_bytes,
            "deduplicated": deduplicated,
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
            "execution_permitted": False,
        }
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=metadata_path.parent,
                prefix=f".{artifact.sha256}.",
                suffix=".metadata.tmp",
                delete=False,
            ) as handle:
                temporary_name = handle.name
                json.dump(metadata, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            temporary = Path(temporary_name)
            try:
                temporary.chmod(0o600)
            except OSError as exc:
                log.debug("Could not apply POSIX metadata mode to %s: %s", temporary, exc)
            os.replace(temporary, metadata_path)
        finally:
            if temporary_name:
                Path(temporary_name).unlink(missing_ok=True)
