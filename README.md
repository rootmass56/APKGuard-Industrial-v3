# APKGuard — Industrial Android APK Security Triage Platform

APKGuard is an evidence-driven Android APK security triage project. It is being rebuilt from a prototype into an industrial-grade platform for static inspection, optional runtime analysis, threat-intelligence enrichment, explainable scoring, and analyst reporting.

> Current release target: **Phase 4 isolated Android runtime-analysis architecture**. Dynamic execution remains fail-closed until a dedicated contained sandbox worker passes every policy and tool preflight gate.

## What APKGuard is building

APKGuard is designed to help analysts answer:

- What permissions, components, APIs, URLs, certificates, and risky indicators exist inside an APK?
- Which findings are directly detected, which are inferred, and which are externally sourced?
- Does reputation intelligence already know the APK hash or related indicators?
- Did real runtime instrumentation observe suspicious behaviour?
- Why did the platform assign a particular risk score?
- What should a security analyst verify next?

## Sprint 0 truth policy

APKGuard now follows these baseline rules:

1. **No fabricated runtime evidence.** Dynamic analysis is marked as `not_executed` unless real runtime instrumentation captures events.
2. **No automatic APK upload to VirusTotal.** VirusTotal integration is hash-only by default.
3. **AI is optional and advisory.** AI summaries explain deterministic evidence; they do not create the final verdict.
4. **ML is advisory until validated.** The current K-Means demo is labelled as a synthetic feature-vector experiment, not a real-world malware benchmark.
5. **Frontend claims must match backend behaviour.** Unsupported claims such as enterprise-ready, zero-day detection, fixed scan time, and no storage have been removed.

## Current capabilities

- FastAPI backend for APK scan orchestration.
- React + Vite frontend dashboard.
- Androguard-based static APK parsing.
- Dangerous permission analysis.
- Suspicious API and string extraction.
- URL and IP extraction.
- Obfuscation and native-library indicators.
- Static behavioural inference with evidence labels.
- Hash-only VirusTotal lookup when configured.
- Optional Groq AI evidence summary when configured.
- Fail-closed isolated Android Emulator adapter with timestamped runtime evidence when a dedicated contained worker is configured.
- Optional Frida observation hooks; logcat and lifecycle collection remain available without Frida.
- PDF report generation prototype.
- URL scanner prototype.
- Synthetic ML demonstration with clear validation warning.

## Planned industrial architecture

```text
Frontend Analyst Dashboard
        |
        v
Secure API Gateway
        |
        v
Scan Orchestrator + Job Queue
        |
        +--> Static Analyzer Worker
        +--> Threat Intelligence Worker
        +--> Dynamic Android Sandbox Worker
        +--> Optional AI Summary Worker
        +--> Report Worker
        |
        v
Evidence Store + Scoring Engine + Reports + SIEM Integrations
```

## Setup

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8000
```

The backend works without Groq or VirusTotal keys. Without keys, those modules report disabled/unavailable states instead of failing the application.

### Frontend

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

## Important environment variables

| Variable | Purpose | Default |
|---|---|---|
| `GROQ_API_KEY` | Enables optional AI explanation | Empty / disabled |
| `VT_API_KEY` | Enables VirusTotal hash lookup | Empty / disabled |
| `APKGUARD_ALLOW_VT_UPLOAD` | Future cloud-enrichment upload gate | `false` |
| `APKGUARD_ENABLE_CACHE` | Local result cache | `true` |
| `APKGUARD_ENABLE_HISTORY` | Local scan history | `true` |
| `APKGUARD_MAX_UPLOAD_MB` | Upload size limit | `100` |
| `APKGUARD_CORS_ORIGINS` | Allowed frontend origins | Local Vite origins |
| `VITE_API_URL` | Frontend backend URL | `http://localhost:8000/api/v1` |
| `APKGUARD_DYNAMIC_MODE` | Runtime analysis mode | `disabled` |
| `APKGUARD_SANDBOX_ENABLED` | Dedicated sandbox worker gate | `false` |

## Verification

```bash
python -m py_compile backend/*.py
cd frontend
npm run lint
npm run build
```

## Known limitations

- Dynamic execution requires a separately hardened Android sandbox host or VM; it is deliberately disabled in local/eager development.
- Phase 4 supports offline runtime execution only. Host-level egress blocking is mandatory.
- UI automation and optional Frida hooks do not guarantee complete runtime coverage.
- The ML benchmark remains synthetic and advisory until the validated ML phase.
- Authentication, RBAC, case management, and production observability are later phases.

## Roadmap

1. **Sprint 0:** Secure and honest baseline.
2. **Phase 1:** Versioned API and typed evidence contracts.
3. **Phase 2:** Persistent jobs, quarantine, Redis/PostgreSQL adapters, and workers.
4. **Phase 3:** Advanced deterministic static analysis and SBOM.
5. **Phase 4:** Fail-closed isolated Android runtime analysis and observed-runtime evidence.
6. **Phase 5:** Repackaging, similarity, and malware lineage.
7. **Phase 6:** Validated machine learning and controlled AI.
8. **Phase 7:** Enterprise workflow, authentication, DevSecOps, and observability.
9. **Phase 8:** Research validation, final release, and submission.

## Ethical use

APKGuard is intended for authorized mobile-security testing, incident response, education, and defensive malware triage. Do not use it to analyze, distribute, execute, or modify malware outside a controlled and authorized environment.

## Industrial v3 Phase 1

The `industrial-v3` branch now uses a versioned `/api/v1` API, canonical evidence and finding schemas, request IDs, standard errors, policy-controlled privacy modes, streamed APK validation, versioned scoring, stage telemetry, and result integrity digests. Root API routes remain temporarily available for frontend compatibility. See `docs/PHASE_1_ARCHITECTURE.md`.


## Phase 2

Persistent scan jobs, content-addressed quarantine, immutable results, real progress, cancellation, retries, timeout controls, PostgreSQL/Redis adapters and Docker Compose are implemented. The Android execution sandbox remains a later phase.


## Phase 3 advanced static analysis

Version `3.2.0-phase3` adds deterministic signing metadata, manifest attack surface, network-security configuration,
TLS/WebView and cryptography rules, dynamic-code indicators, secret redaction, native ELF metadata, SDK inventory,
CycloneDX-style SBOM output, call-graph foundations, and explicitly limited source-to-sink candidates.


## Phase 4 isolated runtime analysis

Version `4.0.0-phase4` introduces a dedicated Android Emulator sandbox adapter, named clean-snapshot startup, allowlisted ADB process execution, offline guest controls, host-egress and dedicated-host policy gates, bounded UI exercise, logcat and filesystem evidence, optional Frida observation hooks, append-only runtime events, session recovery, runtime scoring, and analyst-facing capability/status APIs. The adapter reports `NOT_EXECUTED` unless the environment is explicitly ready.
