# ADR-0001: Versioned API and Canonical Evidence Contracts

- **Status:** Accepted
- **Date:** 2026-07-23
- **Decision owners:** APKGuard Industrial v3 project

## Context

The original prototype returned loosely structured dictionaries from a monolithic FastAPI module. Field mismatches caused integrations to fail silently, scores could diverge from explanations, and inferred behaviour could be confused with runtime evidence.

## Decision

1. All new API clients use `/api/v1`.
2. The React prototype may temporarily use hidden root compatibility routes.
3. Evidence, findings, stages, privacy, scoring, health, and history use Pydantic contracts.
4. Runtime evidence requires `evidence_type=OBSERVED_RUNTIME` and `observed_at_runtime=true`.
5. Every scan records schema, analyzer, evidence-factory, and scoring-policy versions.
6. A result digest covers the normalized evidence-and-score core.
7. External services are governed by an explicit privacy mode.

## Consequences

### Positive

- Schema mismatches fail during validation instead of silently.
- Results can be reproduced and compared across versions.
- AI, inference, threat intelligence, and observed runtime data remain distinguishable.
- New clients have a stable migration target.

### Costs and limitations

- The response is larger because it includes provenance and stage metadata.
- Legacy modules still require adapters during migration.
- Root compatibility routes must eventually be removed after the frontend fully adopts `/api/v1`.
- The result digest is an integrity aid, not a digital signature. Signed reports arrive later.
