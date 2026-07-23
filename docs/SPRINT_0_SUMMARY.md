# APKGuard Industrial Build — Sprint 0 Summary

Sprint 0 converts the uploaded hackathon-style prototype into a safer and more honest baseline for the industrial rebuild.

## Completed corrections

1. **Dynamic evidence correctness**
   - Removed fabricated fallback runtime events from `dynamic_analyzer.py`.
   - Dynamic analysis now returns `status=not_executed` unless real runtime/Frida evidence is captured.
   - Static behaviour inference is labelled separately as `INFERRED_STATIC`.

2. **AI made optional**
   - `ai_engine.py` no longer constructs the Groq client during module import.
   - The backend can run deterministic analysis without `GROQ_API_KEY`.
   - AI output is labelled as an explanation layer, not the source of truth.

3. **VirusTotal privacy correction**
   - VirusTotal is now hash-only by default.
   - Unknown APK upload is blocked until a future explicit consent workflow is implemented.
   - Lookup failures and disabled states are no longer equivalent to "clean".

4. **Score consistency**
   - The ML classifier is advisory only in Sprint 0.
   - ML risk contribution is no longer added to the final score.
   - Final score uses static analysis only unless live runtime evidence exists.

5. **Frontend honesty fixes**
   - Removed fake analysis-stage timing before upload.
   - Replaced unsupported UI claims such as "200+ checks", "~30s", and "No data stored".
   - Replaced "Possible Zero-Day" language with honest high-internal-risk wording.
   - Frontend uses `VITE_API_URL` instead of hard-coded API URLs.

6. **Repository hygiene**
   - Removed backup, patch, and misplaced helper files from the production tree.
   - Added backend `requirements.txt` and `.env.example`.
   - Added frontend `.env.example`.
   - Fixed `batch_tester.py` syntax error and added a synthetic-benchmark warning.

## Verification performed

- `python -m py_compile backend/*.py` passes.
- `npm run lint` passes.
- `npm run build` passes.

## Remaining known limitations

Sprint 0 does not yet make APKGuard production-ready. The following are still planned for later sprints:

- Authentication and role-based access control.
- Job queue and real server-side scan progress.
- PostgreSQL-backed immutable scan records.
- Report generation from scan IDs instead of client-supplied JSON.
- Real Android emulator sandbox with controlled networking.
- Advanced static checks for exported components, signatures, Network Security Config, WebView, TLS, and taint flows.
- Reproducible real-world ML validation with a documented APK corpus.
- CI/CD, Docker, security scanning, and test coverage expansion.

## Sprint 1 target

Sprint 1 should restructure the backend into modules, introduce typed schemas, add a small test suite, and create a job-based scan model. It should also begin replacing the monolithic React component with typed API services and reusable panels.
