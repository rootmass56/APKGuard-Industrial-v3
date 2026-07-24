# Phase 3 Validation Results

## Delivery-environment checks

- Python compilation: passed.
- Backend regression and Phase 3 tests: 43 passed.
- Canonical evidence and finding validation: passed.
- Synthetic APK archive, manifest, code-rule, signing-structure, SBOM, report, and API smoke tests: passed.
- FastAPI import and Phase 3 static-rule metadata endpoint: passed.
- Unsafe Python command-pattern and bare-exception scans: no matches in the delivered source.
- Live APK/AAB/DEX/EXE/DLL samples: not included.

## Required Windows verification

The authoritative workstation gate is `scripts/verify_phase3.ps1`. It must pass Python compilation, pytest, Ruff, Bandit, frontend installation, frontend lint, production build, npm audit, and repository sample-safety checks before commit.

## Honest limitations

- APK v2/v3 signing schemes are structurally identified; cryptographic signature verification remains a controlled-worker task using Android signing tools.
- Source-to-sink output is a bounded candidate analysis, not a complete interprocedural taint proof.
- Dependency versions remain `unknown` unless deterministically recovered, so the engine does not make version-specific CVE claims.
- Static findings do not prove runtime execution. Dynamic evidence remains disabled until the isolated Android sandbox phase.
