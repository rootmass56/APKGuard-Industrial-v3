"""Queue backends for eager local execution and Redis workers."""

from __future__ import annotations

import importlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from app.core.config import Settings

log = logging.getLogger("apkguard.job_queue")


class JobQueue(Protocol):
    backend_name: str

    def enqueue(self, scan_id: str) -> None:
        ...

    def ping(self) -> bool:
        ...


@dataclass(slots=True)
class EagerJobQueue:
    backend_name: str = "eager"

    def enqueue(self, scan_id: str) -> None:
        from app.dependencies import get_job_executor

        get_job_executor().execute(scan_id)

    def ping(self) -> bool:
        return True


class RedisJobQueue:
    backend_name = "redis"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        try:
            redis_module = importlib.import_module("redis")
        except ImportError as exc:
            raise RuntimeError(
                "Redis queue mode requires the 'redis' Python package. Install backend requirements."
            ) from exc
        self.client = redis_module.Redis.from_url(settings.redis_url, decode_responses=True)

    def enqueue(self, scan_id: str) -> None:
        payload = json.dumps(
            {"scan_id": scan_id, "enqueued_at": datetime.now(timezone.utc).isoformat()},
            separators=(",", ":"),
        )
        self.client.lpush(self.settings.redis_queue_name, payload)

    def dequeue(self, timeout_seconds: int = 5) -> str | None:
        item = self.client.brpop(self.settings.redis_queue_name, timeout=max(timeout_seconds, 1))
        if not item:
            return None
        _, payload = item
        data = json.loads(payload)
        return str(data["scan_id"])

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())
        except Exception as exc:
            log.warning("Redis ping failed: %s", exc)
            return False


def create_job_queue(settings: Settings) -> JobQueue:
    if settings.queue_backend == "redis":
        return RedisJobQueue(settings)
    return EagerJobQueue()
