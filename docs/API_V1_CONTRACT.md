# APKGuard API v1 Contract Overview

Base URL during local development:

```text
http://127.0.0.1:8000/api/v1
```

## Core endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Version, privacy mode, capability and execution metadata |
| POST | `/analyze` | Stream, validate and analyze an APK |
| GET | `/history` | Local compatibility history summaries |
| POST | `/scan-url` | Analyze URLs in a message using controlled URL handling |
| GET | `/threat-feeds` | Policy-controlled feed status and summaries |
| POST | `/report` | Compatibility PDF preview; not yet immutable scan-ID reporting |
| GET | `/batch-results` | Clearly labelled synthetic ML experiment |
| POST | `/siem-test` | Explicitly configured SIEM connector test |

## Standard error response

```json
{
  "detail": "Request validation failed.",
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Request validation failed.",
    "details": []
  },
  "request_id": "correlation-id",
  "timestamp": "2026-07-23T00:00:00+00:00"
}
```

## Evidence rule

`OBSERVED_RUNTIME` cannot be emitted unless the event was captured by the future isolated sandbox. Static capabilities use `STATICALLY_DETECTED`; possible behaviour derived from them uses `INFERRED_STATIC`.
