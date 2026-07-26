# Phase 4 Sandbox Runbook

## Safety prerequisite

Use a dedicated disposable host or VM with no personal data, credentials, mounted company shares, cloud tokens, or privileged access to other networks. Apply host firewall or hypervisor rules that deny outbound egress before acknowledging the corresponding configuration gate.

## Tool preparation

Install and validate Android SDK Platform Tools and Android Emulator. Create a dedicated AVD, boot it once, apply the intended baseline configuration, shut down cleanly, and save a named clean snapshot. Optional Frida instrumentation requires a compatible prepared emulator image and matching Frida tooling.

## Preflight-only configuration

Set absolute executable paths where possible and leave runtime disabled initially:

```env
APKGUARD_DYNAMIC_MODE=disabled
APKGUARD_SANDBOX_ENABLED=false
APKGUARD_SANDBOX_ACKNOWLEDGE_ISOLATION_RISK=false
APKGUARD_SANDBOX_DEDICATED_HOST=false
APKGUARD_SANDBOX_HOST_EGRESS_BLOCKED=false
APKGUARD_SANDBOX_AVD_NAME=APKGuard_API_35
APKGUARD_SANDBOX_SNAPSHOT=apkguard-clean
APKGUARD_SANDBOX_NETWORK_MODE=offline
APKGUARD_SANDBOX_INSTRUMENTATION=logcat_only
```

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\sandbox_preflight.ps1
```

The preflight is expected to remain blocked until all execution gates are deliberately enabled.

## Dedicated worker configuration

Only after independent containment validation:

```env
APKGUARD_QUEUE_BACKEND=redis
APKGUARD_ANALYSIS_ISOLATION=subprocess
APKGUARD_DYNAMIC_MODE=isolated_sandbox
APKGUARD_SANDBOX_ENABLED=true
APKGUARD_SANDBOX_ACKNOWLEDGE_ISOLATION_RISK=true
APKGUARD_SANDBOX_DEDICATED_HOST=true
APKGUARD_SANDBOX_HOST_EGRESS_BLOCKED=true
```

Re-run preflight. It must report `ready: true` before starting the sandbox worker.

## First controlled execution

Use only a self-built benign Hello World APK. Submit it through the normal scan API/UI. Confirm:

- job is quarantined and queued
- session state transitions are persisted
- emulator starts from the named snapshot
- offline policy reports applied
- package installs and launches
- observed events include timestamps and digests
- cleanup is confirmed
- emulator stops and snapshot changes are not saved
- no runtime claim appears if the session did not run

## Incident response

If cleanup fails:

1. stop the worker
2. isolate the host or VM
3. terminate emulator processes from the host
4. preserve sandbox logs for investigation
5. discard/revert the worker VM
6. do not reuse the affected AVD snapshot
7. rotate any credentials accidentally present on the host
