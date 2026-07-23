# APKGuard Frontend

React + Vite analyst dashboard for the APKGuard industrial rebuild.

## Setup

```bash
npm install
cp .env.example .env
npm run dev
```

Configure the backend URL in `.env`:

```text
VITE_API_URL=http://localhost:8000
```

## Sprint 0 UI policy

The UI must not claim that an APK is clean when an external lookup is unavailable, must not use zero-day wording for heuristic findings, and must not display fake analysis progress that implies completed backend stages before upload.
