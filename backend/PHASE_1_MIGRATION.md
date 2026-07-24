# Phase 1 Migration Notes

## Uvicorn command

```powershell
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

`backend/main.py` is now only a compatibility ASGI entrypoint. The application factory is `backend/app/main.py`.

## API migration

| Compatibility route | Versioned route |
|---|---|
| `/health` | `/api/v1/health` |
| `/analyze` | `/api/v1/analyze` |
| `/history` | `/api/v1/history` |
| `/report` | `/api/v1/report` |
| `/scan-url` | `/api/v1/scan-url` |
| `/threat-feeds` | `/api/v1/threat-feeds` |
| `/siem-test` | `/api/v1/siem-test` |
| `/batch-results` | `/api/v1/batch-results` |

## Required validation

```powershell
python -m compileall .
python -m pytest -q
ruff check .
bandit -r . -x .\.venv,.\tests
python -c "import main; print(main.APP_VERSION)"
```
