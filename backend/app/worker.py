"""Redis-backed APKGuard scan worker."""

from __future__ import annotations

import logging
import signal
from threading import Event

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import get_database
from app.dependencies import get_job_executor, get_job_queue, get_scan_job_service
from app.services.job_queue import RedisJobQueue

settings = get_settings()
configure_logging(settings.log_level, settings.log_format)
log = logging.getLogger("apkguard.worker")
stop_event = Event()


def _request_stop(_signum, _frame) -> None:
    stop_event.set()


def main() -> None:
    if settings.queue_backend != "redis":
        raise SystemExit("Worker requires APKGUARD_QUEUE_BACKEND=redis.")
    get_database().initialize()
    queue = get_job_queue()
    if not isinstance(queue, RedisJobQueue):
        raise SystemExit("Redis queue adapter is unavailable.")
    recovered = get_scan_job_service().recover_stale_jobs()
    log.info("APKGuard worker started queue=%s recovered=%s", settings.redis_queue_name, recovered)
    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)
    executor = get_job_executor()
    while not stop_event.is_set():
        scan_id = queue.dequeue(timeout_seconds=max(1, int(settings.worker_poll_seconds)))
        if scan_id:
            executor.execute(scan_id)
    log.info("APKGuard worker stopped")


if __name__ == "__main__":
    main()
