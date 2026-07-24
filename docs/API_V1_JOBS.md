# API v1 Scan Jobs

- `POST /api/v1/scans` — validate, quarantine, create and enqueue a scan; returns HTTP 202.
- `GET /api/v1/scans` — list persistent scans.
- `GET /api/v1/scans/{scan_id}` — full job state.
- `GET /api/v1/scans/{scan_id}/progress` — compact real progress contract.
- `GET /api/v1/scans/{scan_id}/events` — ordered immutable job event history.
- `GET /api/v1/scans/{scan_id}/result` — immutable result after COMPLETED/PARTIAL.
- `POST /api/v1/scans/{scan_id}/cancel` — request cancellation.
- `GET /api/v1/scans/{scan_id}/report` — generate a report from the stored immutable result.

The legacy `POST /api/v1/analyze` route remains temporarily available for compatibility.
