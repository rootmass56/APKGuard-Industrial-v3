"""Normalize timestamped sandbox output into canonical observed-runtime events."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from app.schemas.common import SandboxEventCategory, Severity
from app.schemas.dynamic import RuntimeObservation

FRIDA_EVENT_PREFIX = "APKGuardEvent:"
_LOGCAT_RE = re.compile(
    r"^(?P<epoch>\d+(?:\.\d+)?)\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF])\s+(?P<tag>[^:]+):\s?(?P<message>.*)$"
)


def _canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _observation_id(session_id: str, sequence: int, digest: str) -> str:
    return f"obs-{session_id[:8]}-{sequence:05d}-{digest[:12]}"


def _utc_from_epoch(value: str | float | int | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromtimestamp(float(value), timezone.utc)
    except (TypeError, ValueError, OSError):
        return datetime.now(timezone.utc)


def _severity(value: str | None, default: Severity = Severity.INFO) -> Severity:
    try:
        return Severity(str(value or default.value).upper())
    except ValueError:
        return default


def make_observation(
    *,
    session_id: str,
    sequence: int,
    package_name: str,
    category: SandboxEventCategory,
    event_type: str,
    title: str,
    description: str,
    source: str,
    observed_at: datetime,
    severity: Severity = Severity.INFO,
    process_id: int | None = None,
    thread_id: int | None = None,
    payload: dict[str, Any] | None = None,
) -> RuntimeObservation:
    normalized_payload = dict(payload or {})
    digest_payload = {
        "session_id": session_id,
        "package_name": package_name,
        "category": category.value,
        "event_type": event_type,
        "title": title,
        "description": description,
        "source": source,
        "observed_at": observed_at.isoformat(),
        "process_id": process_id,
        "thread_id": thread_id,
        "payload": normalized_payload,
    }
    digest = _canonical_digest(digest_payload)
    return RuntimeObservation(
        observation_id=_observation_id(session_id, sequence, digest),
        category=category,
        event_type=event_type,
        title=title,
        description=description,
        severity=severity,
        observed_at=observed_at,
        source=source,
        package_name=package_name,
        session_id=session_id,
        process_id=process_id,
        thread_id=thread_id,
        payload=normalized_payload,
        evidence_digest=digest,
    )


def parse_frida_events(
    text: str,
    *,
    session_id: str,
    package_name: str,
    start_sequence: int = 1,
) -> list[RuntimeObservation]:
    observations: list[RuntimeObservation] = []
    sequence = start_sequence
    for line in text.splitlines():
        marker = line.find(FRIDA_EVENT_PREFIX)
        if marker < 0:
            continue
        raw = line[marker + len(FRIDA_EVENT_PREFIX) :].strip()
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        category_value = str(event.get("category", "SYSTEM")).upper()
        try:
            category = SandboxEventCategory(category_value)
        except ValueError:
            category = SandboxEventCategory.SYSTEM
        observed_at = _utc_from_epoch(event.get("timestamp_ms", 0) / 1000 if event.get("timestamp_ms") else None)
        observations.append(
            make_observation(
                session_id=session_id,
                sequence=sequence,
                package_name=package_name,
                category=category,
                event_type=str(event.get("event_type", "frida_event")),
                title=str(event.get("title", "Instrumented runtime event")),
                description=str(event.get("description", "A runtime API event was captured by Frida.")),
                source="frida-java-agent",
                observed_at=observed_at,
                severity=_severity(event.get("severity")),
                process_id=_int_or_none(event.get("process_id")),
                thread_id=_int_or_none(event.get("thread_id")),
                payload=dict(event.get("payload") or {}),
            )
        )
        sequence += 1
    return observations


def parse_logcat_events(
    text: str,
    *,
    session_id: str,
    package_name: str,
    start_sequence: int = 1,
) -> list[RuntimeObservation]:
    observations: list[RuntimeObservation] = []
    sequence = start_sequence
    package_lower = package_name.lower()
    for line in text.splitlines():
        match = _LOGCAT_RE.match(line.strip())
        if not match:
            continue
        tag = match.group("tag").strip()
        message = match.group("message").strip()
        combined = f"{tag} {message}".lower()
        if package_lower not in combined and not _is_runtime_signal(combined):
            continue
        category, event_type, title, description, severity = _classify_logcat(tag, message, package_name)
        if category is None:
            continue
        observations.append(
            make_observation(
                session_id=session_id,
                sequence=sequence,
                package_name=package_name,
                category=category,
                event_type=event_type,
                title=title,
                description=description,
                source=f"android-logcat:{tag}",
                observed_at=_utc_from_epoch(match.group("epoch")),
                severity=severity,
                process_id=int(match.group("pid")),
                thread_id=int(match.group("tid")),
                payload={"tag": tag, "level": match.group("level"), "message": message[:2000]},
            )
        )
        sequence += 1
    return observations


def parse_granted_permissions(
    text: str,
    *,
    session_id: str,
    package_name: str,
    start_sequence: int = 1,
) -> list[RuntimeObservation]:
    observations: list[RuntimeObservation] = []
    sequence = start_sequence
    pattern = re.compile(r"(?P<permission>android\.permission\.[A-Z0-9_]+):\s+granted=true")
    for match in pattern.finditer(text):
        permission = match.group("permission")
        observations.append(
            make_observation(
                session_id=session_id,
                sequence=sequence,
                package_name=package_name,
                category=SandboxEventCategory.PERMISSION,
                event_type="runtime_permission_granted",
                title="Runtime permission grant observed",
                description="Android package state reported a granted runtime permission after execution.",
                source="adb-dumpsys-package",
                observed_at=datetime.now(timezone.utc),
                severity=Severity.INFO,
                payload={"permission": permission, "granted": True},
            )
        )
        sequence += 1
    return observations


def parse_process_presence(
    text: str,
    *,
    session_id: str,
    package_name: str,
    start_sequence: int = 1,
) -> list[RuntimeObservation]:
    observations: list[RuntimeObservation] = []
    sequence = start_sequence
    for line in text.splitlines():
        if package_name not in line:
            continue
        columns = line.split()
        pid = next((int(item) for item in columns if item.isdigit()), None)
        observations.append(
            make_observation(
                session_id=session_id,
                sequence=sequence,
                package_name=package_name,
                category=SandboxEventCategory.PROCESS,
                event_type="application_process_observed",
                title="Application process observed",
                description="The package appeared in the Android process table during the sandbox session.",
                source="adb-ps",
                observed_at=datetime.now(timezone.utc),
                severity=Severity.INFO,
                process_id=pid,
                payload={"process_line": line[:1000]},
            )
        )
        sequence += 1
    return observations


def merge_observations(*groups: Iterable[RuntimeObservation]) -> list[RuntimeObservation]:
    unique: dict[str, RuntimeObservation] = {}
    for group in groups:
        for observation in group:
            unique.setdefault(observation.evidence_digest, observation)
    return sorted(unique.values(), key=lambda item: (item.observed_at, item.observation_id))


def dynamic_views(observations: Iterable[RuntimeObservation]) -> dict[str, list[dict[str, Any]]]:
    api_calls: list[dict[str, Any]] = []
    network_calls: list[dict[str, Any]] = []
    file_operations: list[dict[str, Any]] = []
    crypto_operations: list[dict[str, Any]] = []
    for observation in observations:
        payload = observation.payload
        base = {
            "observation_id": observation.observation_id,
            "observed_at": observation.observed_at.isoformat(),
            "threat_level": str(observation.severity).lower(),
        }
        category = str(observation.category)
        if category in {SandboxEventCategory.COMMAND.value, SandboxEventCategory.PROCESS.value}:
            api_calls.append(
                {
                    **base,
                    "api": payload.get("api") or observation.event_type,
                    "class": payload.get("class_name") or observation.source,
                    "args": payload.get("args") or [],
                }
            )
        elif category == SandboxEventCategory.NETWORK.value:
            network_calls.append(
                {
                    **base,
                    "method": payload.get("method") or "CONNECT",
                    "url": payload.get("url"),
                    "host": payload.get("host"),
                    "port": payload.get("port"),
                    "blocked_by_policy": payload.get("blocked_by_policy", False),
                }
            )
        elif category == SandboxEventCategory.FILE.value:
            file_operations.append(
                {
                    **base,
                    "operation": payload.get("operation") or observation.event_type,
                    "path": payload.get("path") or "",
                    "size_bytes": int(payload.get("size_bytes") or 0),
                }
            )
        elif category == SandboxEventCategory.CRYPTO.value:
            crypto_operations.append(
                {
                    **base,
                    "algorithm": payload.get("algorithm") or "unknown",
                    "purpose": payload.get("purpose") or observation.description,
                }
            )
    return {
        "api_calls_intercepted": api_calls,
        "network_calls": network_calls,
        "file_operations": file_operations,
        "crypto_operations": crypto_operations,
    }


def risk_score(observations: Iterable[RuntimeObservation]) -> int:
    weights = {
        Severity.CRITICAL.value: 30,
        Severity.HIGH.value: 18,
        Severity.MEDIUM.value: 8,
        Severity.LOW.value: 3,
        Severity.INFO.value: 0,
    }
    categories: set[str] = set()
    total = 0
    for observation in observations:
        total += weights.get(str(observation.severity), 0)
        categories.add(str(observation.category))
    if len(categories) >= 3:
        total += 5
    return min(100, total)


def _is_runtime_signal(combined: str) -> bool:
    return any(
        marker in combined
        for marker in (
            "fatal exception",
            "anr in ",
            "permission denial",
            "force finishing activity",
            "crash",
        )
    )


def _classify_logcat(
    tag: str,
    message: str,
    package_name: str,
) -> tuple[SandboxEventCategory | None, str, str, str, Severity]:
    lower = f"{tag} {message}".lower()
    if "fatal exception" in lower or "force finishing activity" in lower or "crash" in lower:
        return (
            SandboxEventCategory.CRASH,
            "application_crash",
            "Application crash observed",
            f"Android logcat recorded a crash signal for {package_name}.",
            Severity.HIGH,
        )
    if "anr in " in lower:
        return (
            SandboxEventCategory.CRASH,
            "application_not_responding",
            "Application Not Responding observed",
            f"Android reported an ANR involving {package_name}.",
            Severity.MEDIUM,
        )
    if "permission denial" in lower:
        return (
            SandboxEventCategory.PERMISSION,
            "permission_denial",
            "Runtime permission denial observed",
            "The Android framework denied a permission-protected operation.",
            Severity.LOW,
        )
    if "start proc" in lower or "start u0" in lower or "cmp=" in lower:
        return (
            SandboxEventCategory.LIFECYCLE,
            "application_launch",
            "Application process or activity started",
            f"Android started an activity or process associated with {package_name}.",
            Severity.INFO,
        )
    if "killing" in lower or "force-stop" in lower:
        return (
            SandboxEventCategory.PROCESS,
            "process_termination",
            "Application process terminated",
            f"Android terminated a process associated with {package_name}.",
            Severity.INFO,
        )
    return None, "ignored", "Ignored", "", Severity.INFO


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
