# Phase 2 Local and Docker Runbook

## Local Windows mode

Local mode uses SQLite, content-addressed quarantine storage, and the eager queue. It is designed for development and deterministic verification.

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env -Force
alembic upgrade head
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The frontend uses the asynchronous job API even in eager mode:

```powershell
cd frontend
Set-Content .env "VITE_API_URL=http://localhost:8000/api/v1"
npm ci
npm run dev
```

## Docker Compose mode

Docker mode uses PostgreSQL, Redis, a separate worker, shared quarantine storage, and subprocess analysis boundaries.

```powershell
$env:POSTGRES_PASSWORD = "replace-with-a-development-secret"
docker compose up --build
```

Services:

- Frontend: `http://localhost:5173`
- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`

## Operational checks

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
```

A healthy Docker deployment reports PostgreSQL and Redis as available. Local mode reports SQLite and the eager queue.

## Security boundary

Phase 2 does not execute APKs. The Android dynamic sandbox remains disabled. Quarantine storage is content-addressed and treated as untrusted binary storage only.
