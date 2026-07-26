# API v1 — Dynamic Analysis Control Plane

## Capability discovery

`GET /api/v1/dynamic-analysis/capabilities`

Returns tool availability, configured AVD, policy blockers, warnings, and whether the dedicated sandbox is ready. This endpoint never boots an emulator.

## Policy

`GET /api/v1/dynamic-analysis/policy`

Returns the sandbox policy version, isolation requirements, network constraints, prohibited capabilities, and current blockers.

## Session

`GET /api/v1/dynamic-analysis/sessions/{scan_id}`

Returns the persisted sandbox session associated with a scan. A 404 means no runtime session was created, which is different from a clean runtime result.

## Events

`GET /api/v1/dynamic-analysis/sessions/{scan_id}/events`

Returns ordered, timestamped, append-only runtime events and their evidence digests.

## Execution

There is deliberately no public endpoint that directly executes an arbitrary local file. Runtime analysis is invoked only from the normal persistent scan-job workflow after upload validation, quarantine placement, job authorization, and sandbox policy checks.
