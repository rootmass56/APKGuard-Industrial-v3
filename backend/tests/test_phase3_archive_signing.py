from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from app.static_analysis.archive import inspect_apk_signing_block, inventory_apk


def _write_unsigned_apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest package='com.example'/>")
        archive.writestr("classes.dex", b"dex\n035\x00DexClassLoader AES/ECB/PKCS5Padding")
        archive.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF\x02\x01" + b"\x00" * 12 + struct.pack("<H", 183))


def test_archive_inventory_is_bounded_and_detects_native_metadata(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    _write_unsigned_apk(apk)
    report = inventory_apk(apk)
    assert report["entry_count"] == 3
    assert report["dex_files"] == ["classes.dex"]
    assert report["native_libraries"][0]["format"] == "ELF"
    assert report["native_libraries"][0]["machine"] == "AArch64"
    assert report["signature"]["signing_block_present"] is False


def test_signing_block_inspector_does_not_claim_verification(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    _write_unsigned_apk(apk)
    report = inspect_apk_signing_block(apk)
    assert report["verified"] is False
    assert report["verification_status"] == "not_cryptographically_verified"
