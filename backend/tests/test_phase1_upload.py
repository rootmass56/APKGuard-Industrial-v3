from __future__ import annotations

import asyncio
import io
import zipfile

import pytest
from fastapi import UploadFile

from app.core.config import get_settings
from app.core.errors import InvalidUploadError
from app.services.upload_service import persist_apk_upload


def _apk_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return buffer.getvalue()


def test_valid_apk_is_streamed_hashed_and_structurally_checked():
    upload = UploadFile(filename="safe-test.apk", file=io.BytesIO(_apk_bytes()))
    artifact = asyncio.run(persist_apk_upload(upload, get_settings()))
    try:
        assert len(artifact.sha256) == 64
        assert artifact.size_bytes > 0
        assert artifact.zip_entry_count == 2
        assert artifact.temporary_path.exists()
    finally:
        artifact.cleanup()


def test_non_apk_extension_is_rejected():
    upload = UploadFile(filename="sample.zip", file=io.BytesIO(_apk_bytes()))
    with pytest.raises(InvalidUploadError):
        asyncio.run(persist_apk_upload(upload, get_settings()))


def test_missing_manifest_is_rejected():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("classes.dex", b"dex")
    upload = UploadFile(filename="invalid.apk", file=io.BytesIO(buffer.getvalue()))

    with pytest.raises(InvalidUploadError):
        asyncio.run(persist_apk_upload(upload, get_settings()))


def test_unsafe_archive_path_is_rejected():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("../escape.txt", b"unsafe")
    upload = UploadFile(filename="unsafe.apk", file=io.BytesIO(buffer.getvalue()))

    with pytest.raises(InvalidUploadError):
        asyncio.run(persist_apk_upload(upload, get_settings()))
