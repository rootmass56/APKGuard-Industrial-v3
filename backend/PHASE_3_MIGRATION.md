# Phase 3 Migration

1. Install `cryptography` from `requirements.txt`.
2. Run `scripts/verify_phase3.ps1`.
3. Existing Phase 2 database migrations remain current; Phase 3 changes the result schema, not relational tables.
4. Old cached result files are invalidated by schema version `1.2`.
