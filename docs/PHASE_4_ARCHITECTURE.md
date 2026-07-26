# Phase 4 Architecture — Isolated Android Runtime Analysis

## Objective

Phase 4 adds a controlled adapter for executing an authorized APK in a disposable Android Emulator session and creating timestamped `OBSERVED_RUNTIME` evidence. It does not convert static indicators into runtime claims.

## Trust boundaries

```text
Analyst / Frontend
       |
       v
API + PostgreSQL + Redis
       |
       v
Dedicated Sandbox Worker Host or VM
       |
       +-- content-addressed quarantine (read-only input intent)
       +-- Android Emulator AVD + named clean snapshot
       +-- ADB allowlisted command adapter
       +-- optional Frida observation agent
       +-- logcat / package dump / screenshot / file inventory
       |
       v
Append-only sandbox sessions and runtime events
```

The generic API and static worker containers keep dynamic execution disabled. The Android SDK, emulator, and optional Frida tooling belong on a separately hardened sandbox worker host or VM.

## Fail-closed policy

Execution is blocked unless configuration confirms all of the following:

1. `APKGUARD_DYNAMIC_MODE=isolated_sandbox`
2. sandbox explicitly enabled
3. isolation risk acknowledged
4. dedicated sandbox host or VM acknowledged
5. host-level outbound egress is blocked
6. Redis-backed dedicated worker deployment
7. subprocess analysis boundary
8. configured AVD and clean snapshot
9. offline guest network policy
10. ADB root prohibited
11. APK path resolves inside content-addressed quarantine
12. required tools and AVD pass preflight

The API reports blockers without booting an emulator.

## Session state machine

```text
CREATED -> PREFLIGHT -> STARTING -> BOOTING -> ISOLATING
        -> INSTALLING -> INSTRUMENTING -> INTERACTING
        -> COLLECTING -> TEARDOWN -> COMPLETED

Terminal alternatives: FAILED, CANCELLED, TIMED_OUT
```

Every transition is persisted. Worker startup recovers stale sessions, and cancellation/timeout performs a best-effort emulator teardown before marking the session failed.

## Runtime collection

The baseline can collect:

- emulator lifecycle and boot evidence
- package installation and launch status
- bounded package-scoped Monkey UI events
- epoch-formatted logcat records
- Android Emulator virtual-network PCAP capture while the guest remains under offline policy
- package metadata from `dumpsys package`
- package-private file inventory when `run-as` is permitted
- before/after file differences
- runtime screenshot
- optional Frida observations for selected Java APIs
- artifact hashes and sizes

Frida is optional by default. When unavailable, the session can still produce logcat and lifecycle evidence. A required-Frida policy blocks execution when the tool is missing.

## Evidence integrity

Each observation includes:

- stable observation ID
- session ID and sequence
- UTC observation time
- category and event type
- source adapter
- package name
- redacted/structured payload
- SHA-256 evidence digest

Runtime evidence uses the canonical `OBSERVED_RUNTIME` evidence type. Static findings remain `STATICALLY_DETECTED` or `INFERRED_STATIC`.

## Network policy

Phase 4 supports only `offline`. The worker applies airplane mode, disables Wi-Fi and mobile data, clears proxy configuration, and disables private DNS inside the guest. These guest controls are defense-in-depth; the host or VM must independently block outbound network access before the policy gate is enabled.

## Current limitations

- No unrestricted internet detonation.
- No claim that guest controls alone form a complete containment boundary.
- Snapshot availability is proven only when the emulator starts.
- `run-as` filesystem inventory is unavailable for many release APKs.
- Frida requires a separately prepared compatible emulator image/server.
- UI automation is bounded and does not guarantee full application coverage.
- The baseline stores emulator PCAP artifacts but does not yet perform TLS interception or full protocol reconstruction.
- Tests use deterministic fake tool adapters; the delivery environment did not execute an Android image.
