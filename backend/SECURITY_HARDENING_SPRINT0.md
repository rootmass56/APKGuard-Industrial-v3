# APKGuard Sprint 0 Security Hardening Checkpoint

## Purpose

This checkpoint removes unsafe prototype execution paths before the industrial
architecture rebuild begins. It is a foundation release, not the final dynamic
sandbox or production deployment.

## Security changes

- SHA-256 is the authoritative sample digest.
- MD5 and SHA-1 are generated only as historical threat-intelligence identifiers
  with `usedforsecurity=False`.
- Direct ADB/Frida execution from the FastAPI host is disabled.
- Legacy Frida-gadget APK injection is disabled and cannot execute shell commands.
- The dynamic-analysis API returns `not_executed` until an isolated sandbox worker exists.
- Static behavioural inference is explicitly labelled `INFERRED_STATIC` and never observed.
- APK uploads are streamed to a private temporary file with an enforced size limit.
- Unknown APK files are not uploaded to VirusTotal.
- PDF output uses output escaping and does not invent benchmark results.
- Silent cache/history cleanup failures now generate logs.
- Core dependencies no longer require Frida or Groq; AI remains optional.

## Intentional limitations

- Dynamic execution is unavailable in Sprint 0.
- The K-Means module remains a synthetic advisory experiment and contributes zero
  points to the final risk score.
- The report endpoint still accepts client-supplied data and must be replaced with
  immutable scan-ID report generation during the persistent job architecture sprint.
- Authentication, RBAC, PostgreSQL, Redis, worker isolation, and quarantine storage
  are industrial-target work, not claims of this checkpoint.

## Required local verification

```powershell
python -m compileall .
python -m pytest -q
ruff check .
bandit -r . -x .\.venv,.\tests
python -c "import main; print('BACKEND IMPORT SUCCESSFUL')"
```

Acceptance target:

- Compile: pass
- Pytest: all tests pass
- Ruff: all checks pass
- Bandit: zero high and zero medium findings
- Backend import: pass without API keys
