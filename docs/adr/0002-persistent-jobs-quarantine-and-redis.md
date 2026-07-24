# ADR 0002: Persistent jobs, quarantine and Redis workers

## Decision

Use SQLAlchemy as the persistence boundary, PostgreSQL as the deployment database, SQLite as the local/test fallback, a content-addressed filesystem quarantine for APK bytes, and Redis as the deployment queue.

## Rationale

- APKs are large untrusted binaries and should not be placed in ordinary relational rows.
- SHA-256 content addressing provides deterministic naming and storage deduplication.
- Persistent jobs and ordered events permit recovery, auditing and truthful progress.
- PostgreSQL supports transactional multi-worker deployments.
- Redis provides a simple, inspectable queue boundary without coupling the domain model to a task framework.
- SQLite/eager mode keeps local setup and tests reproducible.

## Consequences

- Production requires PostgreSQL, Redis, shared quarantine storage and at least one worker.
- A database migration must accompany persistence schema changes.
- The legacy synchronous endpoint is compatibility-only and will not be the primary frontend path.
