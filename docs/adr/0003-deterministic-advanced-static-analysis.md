# ADR 0003: Deterministic advanced static analysis

## Decision

APKGuard will generate primary Phase 3 findings using deterministic rules with stable evidence identifiers. LLM output
may explain findings but cannot create evidence, change rule severity, or alter the scoring policy.

## Consequences

Results are reproducible and auditable. Some findings remain conservative because static presence and bounded call paths
do not prove runtime execution or exploitability.
