"""Per-request correlation context."""

from __future__ import annotations

import re
from contextvars import ContextVar, Token
from uuid import uuid4

_REQUEST_ID: ContextVar[str] = ContextVar("apkguard_request_id", default="system")
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def normalize_request_id(value: str | None) -> str:
    candidate = (value or "").strip()
    if candidate and _VALID_REQUEST_ID.fullmatch(candidate):
        return candidate
    return str(uuid4())


def set_request_id(value: str) -> Token[str]:
    return _REQUEST_ID.set(value)


def reset_request_id(token: Token[str]) -> None:
    _REQUEST_ID.reset(token)


def get_request_id() -> str:
    return _REQUEST_ID.get()
