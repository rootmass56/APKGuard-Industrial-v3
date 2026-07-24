"""Shared utilities for bounded, deterministic static analysis."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import Any

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def stable_id(prefix: str, *parts: Any) -> str:
    material = "\x1f".join(str(part or "") for part in parts)
    digest = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_strings(data: bytes, *, max_strings: int = 10000, max_length: int = 512) -> list[str]:
    """Extract bounded ASCII and UTF-16LE strings without interpreting executable code."""
    values: set[str] = set()
    for match in _PRINTABLE.finditer(data):
        values.add(match.group(0)[:max_length].decode("utf-8", errors="ignore"))
        if len(values) >= max_strings:
            break
    if len(values) < max_strings:
        for match in _UTF16LE.finditer(data):
            values.add(match.group(0)[: max_length * 2].decode("utf-16le", errors="ignore"))
            if len(values) >= max_strings:
                break
    return sorted(value for value in values if value)


def redact(value: str, *, visible: int = 4) -> str:
    if len(value) <= visible * 2:
        return "*" * len(value)
    return f"{value[:visible]}…{value[-visible:]}"


def bounded_unique(values: Iterable[str], limit: int) -> list[str]:
    return sorted({value for value in values if value})[:limit]
