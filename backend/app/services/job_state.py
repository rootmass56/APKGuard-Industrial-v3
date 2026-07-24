"""Validated Phase 2 scan-job state machine."""

from __future__ import annotations

from app.schemas.common import JobState


TERMINAL_STATES = {
    JobState.COMPLETED,
    JobState.PARTIAL,
    JobState.FAILED,
    JobState.CANCELLED,
    JobState.TIMED_OUT,
}

ALLOWED_TRANSITIONS: dict[JobState, set[JobState]] = {
    JobState.CREATED: {JobState.VALIDATING, JobState.FAILED, JobState.CANCELLED},
    JobState.VALIDATING: {JobState.QUARANTINED, JobState.FAILED, JobState.CANCELLED},
    JobState.QUARANTINED: {JobState.QUEUED, JobState.FAILED, JobState.CANCELLED},
    JobState.QUEUED: {JobState.RUNNING, JobState.CANCELLED, JobState.FAILED},
    JobState.RUNNING: {
        JobState.QUEUED,
        JobState.CANCEL_REQUESTED,
        JobState.COMPLETED,
        JobState.PARTIAL,
        JobState.FAILED,
        JobState.CANCELLED,
        JobState.TIMED_OUT,
    },
    JobState.CANCEL_REQUESTED: {
        JobState.CANCELLED,
        JobState.COMPLETED,
        JobState.PARTIAL,
        JobState.FAILED,
        JobState.TIMED_OUT,
        JobState.QUEUED,
    },
    JobState.COMPLETED: set(),
    JobState.PARTIAL: set(),
    JobState.FAILED: set(),
    JobState.CANCELLED: set(),
    JobState.TIMED_OUT: set(),
}

STATE_PROGRESS: dict[JobState, int] = {
    JobState.CREATED: 0,
    JobState.VALIDATING: 10,
    JobState.QUARANTINED: 20,
    JobState.QUEUED: 30,
    JobState.RUNNING: 45,
    JobState.CANCEL_REQUESTED: 70,
    JobState.COMPLETED: 100,
    JobState.PARTIAL: 100,
    JobState.FAILED: 100,
    JobState.CANCELLED: 100,
    JobState.TIMED_OUT: 100,
}


def validate_transition(current: JobState, target: JobState) -> None:
    if target not in ALLOWED_TRANSITIONS[current]:
        raise ValueError(f"Invalid scan-job transition: {current.value} -> {target.value}")


def is_terminal(state: JobState) -> bool:
    return state in TERMINAL_STATES
