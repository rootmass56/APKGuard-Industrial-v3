# Phase 4 Migration

APKGuard Phase 4 upgrades the application to `4.0.0-phase4` and schema `1.3`.

## Database

Apply the new migration before starting the API or workers:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
alembic upgrade head
```

The migration adds `sandbox_sessions` and `sandbox_events`. Runtime events are append-only evidence records; completed events are not edited in place.

## Safe default

Dynamic execution remains disabled after migration. A normal local development `.env` continues to run static analysis only.

## Dedicated sandbox worker

Runtime execution is permitted only when all fail-closed gates are explicitly satisfied on a dedicated worker host or VM:

- Redis queue
- subprocess analysis isolation
- dedicated AVD and clean snapshot
- dedicated-host acknowledgement
- host-level egress blocking acknowledgement
- offline guest policy
- ADB root disabled
- explicit isolation-risk acknowledgement

Never enable these options on an ordinary workstation containing personal or company data.
