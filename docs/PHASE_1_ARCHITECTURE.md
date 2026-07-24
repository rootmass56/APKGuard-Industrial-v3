# APKGuard Industrial v3 — Phase 1 Architecture

## Status

Phase 1 introduces professional application boundaries without claiming that the future queue, database, or Android sandbox already exists.

## Implemented

- FastAPI application factory in `backend/app/main.py`.
- Versioned API under `/api/v1`.
- Hidden root compatibility routes for the current React frontend.
- Central immutable configuration in `app/core/config.py`.
- Request correlation through `X-Request-ID`.
- Standard error contract with stable error codes.
- Canonical evidence, finding, stage, privacy, score, health, and history Pydantic models.
- Stable evidence/finding identifiers.
- Versioned score policy wrapper.
- Explicit privacy modes controlling external lookups and AI.
- Atomic local JSON cache/history repositories as temporary Phase 1 adapters.
- Streamed APK intake with basic archive-structure, path, size, entry-count, and compression-ratio checks.
- Result integrity digest over the versioned evidence/scoring core.
- Structured stage status and analyzer versions.

## Compatibility boundary

The frontend still calls `/analyze`, `/history`, and related root endpoints. Those routes remain operational but are hidden from OpenAPI. New clients must use `/api/v1/...`.

## Honest limitations

- Analysis is still synchronous in Phase 1.
- Cache/history are local JSON adapters, not PostgreSQL.
- Dynamic analysis remains not executed until the isolated Android sandbox is implemented.
- The current ML component is synthetic and advisory only.
- The report endpoint remains a compatibility preview and does not yet load immutable scan records by scan ID.

## Phase 2 migration targets

- PostgreSQL and migrations.
- Redis-backed queue.
- Background worker state machine.
- Quarantined object storage.
- Real job progress and cancellation.
- Immutable report generation from stored scan IDs.
