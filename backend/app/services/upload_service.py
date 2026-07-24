"""Streamed APK intake with bounded structural validation."""

from __future__ import annotations

import hashlib
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from fastapi import UploadFile

from app.core.config import Settings
from app.core.errors import InvalidUploadError


@dataclass(frozen=True, slots=True)
class UploadArtifact:
    original_filename: str
    temporary_path: Path
    sha256: str
    size_bytes: int
    zip_entry_count: int
    total_uncompressed_bytes: int

    def cleanup(self) -> None:
        self.temporary_path.unlink(missing_ok=True)


def _safe_filename(filename: str | None) -> str:
    normalized = Path(filename or "").name.strip()
    if not normalized:
        raise InvalidUploadError("Uploaded APK filename is missing.")
    if not normalized.lower().endswith(".apk"):
        raise InvalidUploadError("Only .apk files are accepted.")
    return normalized


def _validate_archive(path: Path, settings: Settings) -> tuple[int, int]:
    if not zipfile.is_zipfile(path):
        raise InvalidUploadError("File does not contain a valid ZIP/APK structure.")

    try:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            if len(entries) > settings.max_zip_entries:
                raise InvalidUploadError(
                    "APK contains too many archive entries.",
                    details={"limit": settings.max_zip_entries, "actual": len(entries)},
                )

            filenames = {entry.filename for entry in entries}
            if "AndroidManifest.xml" not in filenames:
                raise InvalidUploadError("APK is missing AndroidManifest.xml.")

            total_uncompressed = 0
            for entry in entries:
                if entry.is_dir():
                    continue
                pure = PurePosixPath(entry.filename)
                if pure.is_absolute() or ".." in pure.parts:
                    raise InvalidUploadError("APK contains an unsafe archive path.")

                total_uncompressed += int(entry.file_size)
                if total_uncompressed > settings.max_uncompressed_bytes:
                    raise InvalidUploadError(
                        "APK exceeds the configured uncompressed-size limit.",
                        details={"limit_bytes": settings.max_uncompressed_bytes},
                    )

                if entry.file_size >= 1024 * 1024:
                    ratio = entry.file_size / max(entry.compress_size, 1)
                    if ratio > settings.max_compression_ratio:
                        raise InvalidUploadError(
                            "APK contains an entry with an unsafe compression ratio.",
                            details={
                                "entry": entry.filename,
                                "ratio": round(ratio, 2),
                                "limit": settings.max_compression_ratio,
                            },
                        )
            return len(entries), total_uncompressed
    except zipfile.BadZipFile as exc:
        raise InvalidUploadError("APK archive could not be parsed.") from exc


async def persist_apk_upload(upload: UploadFile, settings: Settings) -> UploadArtifact:
    filename = _safe_filename(upload.filename)
    digest = hashlib.sha256()
    total_bytes = 0
    first_bytes = b""
    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as temporary_file:
            temporary_path = Path(temporary_file.name)
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                if not first_bytes:
                    first_bytes = chunk[:4]
                total_bytes += len(chunk)
                if total_bytes > settings.max_upload_bytes:
                    raise InvalidUploadError(
                        f"APK exceeds configured {settings.max_upload_mb} MB upload limit.",
                        too_large=True,
                    )
                digest.update(chunk)
                temporary_file.write(chunk)

        if total_bytes == 0:
            raise InvalidUploadError("Uploaded APK is empty.")
        if not first_bytes.startswith(b"PK"):
            raise InvalidUploadError("File does not look like an APK/ZIP archive.")

        entry_count, total_uncompressed = _validate_archive(temporary_path, settings)
        return UploadArtifact(
            original_filename=filename,
            temporary_path=temporary_path,
            sha256=digest.hexdigest(),
            size_bytes=total_bytes,
            zip_entry_count=entry_count,
            total_uncompressed_bytes=total_uncompressed,
        )
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()
