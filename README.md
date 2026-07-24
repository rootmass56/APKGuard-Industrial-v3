# APKGuard — Industrial Android APK Security Triage Platform

APKGuard is an evidence-driven Android APK security triage project. It is being rebuilt from a prototype into an industrial-grade platform for static inspection, optional runtime analysis, threat-intelligence enrichment, explainable scoring, and analyst reporting.

> Current branch status: **Sprint 0 industrial baseline**. This is not yet a production malware sandbox or enterprise SOC product. The project now avoids known false claims and clearly separates observed evidence from inferred indicators.

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
- Optional Frida runtime capture when a compatible Android runtime is already available.
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
| `VITE_API_URL` | Frontend backend URL | `http://localhost:8000` |

## Verification

```bash
python -m py_compile backend/*.py
cd frontend
npm run lint
npm run build
```

## Known limitations

- The dynamic sandbox is not yet a complete isolated Android emulator pipeline.
- The ML benchmark is synthetic and not a real-world malware evaluation.
- The report endpoint still accepts client-supplied data in Sprint 0.
- Authentication, RBAC, audit logging, database persistence, and job queues are planned for later sprints.
- Advanced static-analysis modules such as certificate analysis, exported-component analysis, taint analysis, and repackaging comparison are planned but not complete.

## Roadmap

1. **Sprint 0:** Truth, safety, dependency setup, and baseline verification.
2. **Sprint 1:** Typed backend schemas, modular architecture, tests, and job model.
3. **Sprint 2:** Advanced static-analysis checks and standards mapping.
4. **Sprint 3:** Real dynamic Android sandbox and runtime timeline.
5. **Sprint 4:** Threat-intelligence correlation, similarity graph, and repackaging detection.
6. **Sprint 5:** Reproducible ML dataset and ablation study.
7. **Sprint 6:** Enterprise workflow, reports from immutable scan IDs, SIEM/STIX integrations, Docker and CI/CD.

## Ethical use

APKGuard is intended for authorized mobile-security testing, incident response, education, and defensive malware triage. Do not use it to analyze, distribute, execute, or modify malware outside a controlled and authorized environment.

## Industrial v3 Phase 1

The `industrial-v3` branch now uses a versioned `/api/v1` API, canonical evidence and finding schemas, request IDs, standard errors, policy-controlled privacy modes, streamed APK validation, versioned scoring, stage telemetry, and result integrity digests. Root API routes remain temporarily available for frontend compatibility. See `docs/PHASE_1_ARCHITECTURE.md`.


## Phase 2

Persistent scan jobs, content-addressed quarantine, immutable results, real progress, cancellation, retries, timeout controls, PostgreSQL/Redis adapters and Docker Compose are implemented. The Android execution sandbox remains a later phase.
