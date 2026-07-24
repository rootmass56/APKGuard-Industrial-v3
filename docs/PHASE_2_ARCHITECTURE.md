# Phase 2 — Persistent and Asynchronous Analysis Platform

Phase 2 converts APKGuard from a synchronous compatibility scanner into a persistent scan-job platform.

## Implemented architecture

- SQLAlchemy persistence with SQLite for zero-dependency local development and PostgreSQL in Docker Compose.
- Alembic migration for artifacts, scan jobs, ordered events, and immutable results.
- Content-addressed quarantine using SHA-256 paths, atomic writes, integrity re-verification, restrictive permissions, and deduplication.
- Job states: CREATED, VALIDATING, QUARANTINED, QUEUED, RUNNING, CANCEL_REQUESTED, COMPLETED, PARTIAL, FAILED, CANCELLED, TIMED_OUT.
- Eager queue for local verification and Redis list queue for API/worker deployments.
- Real API-reported progress, ordered event history, retry accounting, heartbeat metadata, stale-job recovery, cancellation checkpoints, and subprocess timeout support.
- Immutable result storage: a scan ID can receive one result payload only.
- Stored scan-ID PDF reports.

## Honest boundaries

- SQLite/eager mode is intended for local development and tests, not horizontal scale.
- Redis/PostgreSQL mode requires Docker Compose or separately managed services.
- Inline execution cannot interrupt a running analyzer immediately; hard cancellation and timeouts are enforced by the subprocess worker mode.
- The Android runtime sandbox is not part of Phase 2 and remains disabled.
