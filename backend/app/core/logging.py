"""Structured logging configuration with request correlation."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.core.context import get_request_id

_CONFIGURED = False


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", get_request_id()),
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO", log_format: str = "text") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler()
    handler.addFilter(RequestContextFilter())
    if log_format == "json":
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)s | %(name)s | request_id=%(request_id)s | %(message)s"
            )
        )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    _CONFIGURED = True
