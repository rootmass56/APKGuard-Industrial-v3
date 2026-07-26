# ADR 0004 — Fail-Closed Isolated Android Sandbox

## Status

Accepted for Phase 4.

## Decision

Runtime analysis is permitted only through a dedicated Redis worker using subprocess isolation, a content-addressed quarantined APK, a named Android Emulator snapshot, an offline-only guest policy, host-level egress blocking, and explicit operator acknowledgements. Direct execution from the API process and host-shell command construction are prohibited.

## Rationale

APK execution is materially more dangerous than static inspection. A policy gate must distinguish “adapter implemented” from “environment safe and ready.” Persisted states and timestamped observations provide an auditable boundary between runtime evidence, static evidence, and inference.

## Consequences

- Local eager development remains static-only.
- Generic Docker workers remain dynamic-disabled.
- A separately administered Android sandbox host or VM is required.
- Missing tools or containment controls produce `NOT_EXECUTED`, not a clean verdict.
- Dynamic results can be partial and must preserve limitations.
