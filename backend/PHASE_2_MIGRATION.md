# Phase 2 Migration Notes

1. Install the updated core and development requirements.
2. Add the new database, queue, quarantine, retry, timeout and isolation settings from `.env.example`.
3. Run `alembic upgrade head` before using PostgreSQL or a fresh SQLite database with auto-creation disabled.
4. Use `POST /api/v1/scans` as the primary intake endpoint. The synchronous `/api/v1/analyze` endpoint remains compatibility-only.
5. In Redis mode, run `python -m app.worker` in a separate process.
6. Completed results are immutable. Do not update `scan_results` rows; create a new scan/version for corrected analysis.
7. Do not place APKs in the database. Only quarantine paths and metadata belong in relational storage.
