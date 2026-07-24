"""Safe APK archive inventory, signing-block inspection, certificates, and native metadata."""

from __future__ import annotations

import hashlib
import logging
import struct
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.static_analysis.util import extract_strings, sha256_bytes

log = logging.getLogger("apkguard.static.archive")

APK_SIG_MAGIC = b"APK Sig Block 42"
APK_SIGNATURE_IDS = {
    0x7109871A: "v2",
    0xF05368C0: "v3",
    0x1B93AD61: "v3.1",
    0x04234F31: "source_stamp",
}
ELF_MACHINES = {
    3: "x86",
    40: "ARM",
    62: "x86_64",
    183: "AArch64",
    243: "RISC-V",
}


def _find_eocd(data: bytes) -> int | None:
    start = max(0, len(data) - (65535 + 22))
    position = data.rfind(b"PK\x05\x06", start)
    return position if position >= 0 else None


def inspect_apk_signing_block(path: Path) -> dict[str, Any]:
    """Detect APK Signature Scheme IDs without claiming cryptographic verification."""
    result: dict[str, Any] = {
        "signing_block_present": False,
        "detected_schemes": [],
        "signer_blocks": [],
        "verified": False,
        "verification_status": "not_cryptographically_verified",
    }
    try:
        data = path.read_bytes()
    except OSError as exc:
        result["error"] = str(exc)
        return result
    eocd = _find_eocd(data)
    if eocd is None or eocd + 20 > len(data):
        return result
    central_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    if central_offset < 24 or central_offset > len(data):
        return result
    footer = data[central_offset - 24 : central_offset]
    if len(footer) != 24 or footer[8:] != APK_SIG_MAGIC:
        return result
    size_in_footer = struct.unpack_from("<Q", footer, 0)[0]
    block_start = central_offset - (size_in_footer + 8)
    if block_start < 0 or block_start + 8 > len(data):
        return result
    size_in_header = struct.unpack_from("<Q", data, block_start)[0]
    if size_in_header != size_in_footer:
        result["error"] = "APK signing block size mismatch"
        return result
    result["signing_block_present"] = True
    cursor = block_start + 8
    pairs_end = central_offset - 24
    schemes: set[str] = set()
    blocks: list[dict[str, Any]] = []
    while cursor + 8 <= pairs_end:
        pair_size = struct.unpack_from("<Q", data, cursor)[0]
        cursor += 8
        if pair_size < 4 or cursor + pair_size > pairs_end:
            result["parse_status"] = "partial"
            break
        block_id = struct.unpack_from("<I", data, cursor)[0]
        value_size = int(pair_size - 4)
        name = APK_SIGNATURE_IDS.get(block_id, f"unknown_0x{block_id:08x}")
        blocks.append({"id": f"0x{block_id:08x}", "name": name, "value_size": value_size})
        if name in {"v2", "v3", "v3.1"}:
            schemes.add(name)
        cursor += pair_size
    result["detected_schemes"] = sorted(schemes)
    result["signer_blocks"] = blocks[:32]
    return result


def _certificate_details(data: bytes, entry_name: str) -> list[dict[str, Any]]:
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError:
        return []
    try:
        certificates = pkcs7.load_der_pkcs7_certificates(data)
    except ValueError:
        try:
            certificates = pkcs7.load_pem_pkcs7_certificates(data)
        except ValueError:
            return []
    now = datetime.now(timezone.utc)
    output: list[dict[str, Any]] = []
    for cert in certificates[:8]:
        not_before = getattr(cert, "not_valid_before_utc", None)
        if not_before is None:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = getattr(cert, "not_valid_after_utc", None)
        if not_after is None:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        public_key = cert.public_key()
        output.append(
            {
                "entry": entry_name,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": hex(cert.serial_number),
                "sha256": None,
                "not_valid_before": not_before.isoformat(),
                "not_valid_after": not_after.isoformat(),
                "expired": not_after < now,
                "not_yet_valid": not_before > now,
                "self_signed_subject_match": cert.subject == cert.issuer,
                "public_key_type": type(public_key).__name__,
                "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
            }
        )
    # hashlib objects are not accepted by cryptography fingerprint(); compute DER digest instead.
    for item, cert in zip(output, certificates, strict=False):
        from cryptography.hazmat.primitives.serialization import Encoding

        item["sha256"] = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    return output


def inspect_v1_certificates(archive: zipfile.ZipFile) -> dict[str, Any]:
    signature_entries = sorted(
        info.filename
        for info in archive.infolist()
        if not info.is_dir()
        and info.filename.upper().startswith("META-INF/")
        and info.filename.upper().endswith((".RSA", ".DSA", ".EC"))
    )
    certificates: list[dict[str, Any]] = []
    for name in signature_entries[:16]:
        try:
            data = archive.read(name)
        except (KeyError, OSError, RuntimeError) as exc:
            log.debug("Unable to read signature entry %s: %s", name, exc)
            continue
        certificates.extend(_certificate_details(data, name))
    return {
        "v1_signature_entries": signature_entries,
        "v1_present": bool(signature_entries),
        "certificates": certificates,
        "certificate_parse_status": "parsed" if certificates else "unavailable_or_no_certificates",
    }


def inspect_native_entry(name: str, data: bytes) -> dict[str, Any]:
    item: dict[str, Any] = {
        "path": name,
        "size_bytes": len(data),
        "sha256": sha256_bytes(data),
        "format": "unknown",
    }
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return item
    elf_class = data[4]
    endian = data[5]
    fmt = "<" if endian == 1 else ">" if endian == 2 else None
    item.update(
        {
            "format": "ELF",
            "bitness": 32 if elf_class == 1 else 64 if elf_class == 2 else None,
            "endianness": "little" if endian == 1 else "big" if endian == 2 else "unknown",
        }
    )
    if fmt:
        machine = struct.unpack_from(f"{fmt}H", data, 18)[0]
        item["machine"] = ELF_MACHINES.get(machine, f"unknown_{machine}")
    path_parts = name.split("/")
    item["abi"] = path_parts[1] if len(path_parts) > 2 else None
    return item


def inventory_apk(
    path: Path,
    *,
    max_entry_bytes: int = 8 * 1024 * 1024,
    max_total_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Build a bounded archive inventory and string corpus for deterministic rules."""
    result: dict[str, Any] = {
        "entries": [],
        "dex_files": [],
        "native_libraries": [],
        "embedded_archives": [],
        "signature": {},
        "strings_by_entry": {},
        "limitations": [],
    }
    consumed = 0
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        result["entry_count"] = len(infos)
        result["signature"] = inspect_v1_certificates(archive)
        for info in infos:
            if info.is_dir():
                continue
            name = info.filename
            lower = name.lower()
            result["entries"].append(
                {
                    "path": name,
                    "compressed_size": info.compress_size,
                    "uncompressed_size": info.file_size,
                    "crc32": f"{info.CRC:08x}",
                }
            )
            if lower.endswith(".dex"):
                result["dex_files"].append(name)
            if lower.startswith("lib/") and lower.endswith(".so"):
                try:
                    native_data = archive.read(info) if info.file_size <= max_entry_bytes else b""
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    native_data = b""
                result["native_libraries"].append(inspect_native_entry(name, native_data))
            if lower.endswith((".apk", ".jar", ".zip", ".dex")) and not lower.startswith("classes"):
                result["embedded_archives"].append(name)
            if info.file_size > max_entry_bytes or consumed + info.file_size > max_total_bytes:
                continue
            if not lower.endswith((".dex", ".xml", ".json", ".js", ".html", ".txt", ".properties", ".cfg", ".conf")):
                continue
            try:
                data = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            consumed += len(data)
            strings = extract_strings(data, max_strings=4000)
            if strings:
                result["strings_by_entry"][name] = strings
        result["entry_inventory_truncated"] = len(result["entries"]) > 2000
        result["entries"] = result["entries"][:2000]
    result["dex_files"] = sorted(result["dex_files"])
    result["embedded_archives"] = sorted(result["embedded_archives"])
    result["native_libraries"] = sorted(result["native_libraries"], key=lambda item: item["path"])
    result["scanned_uncompressed_bytes"] = consumed
    result["signature"].update(inspect_apk_signing_block(path))
    return result
