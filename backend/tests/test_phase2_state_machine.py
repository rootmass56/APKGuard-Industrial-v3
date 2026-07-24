import pytest

from app.schemas.common import JobState
from app.services.job_state import is_terminal, validate_transition


def test_valid_job_transitions():
    validate_transition(JobState.CREATED, JobState.VALIDATING)
    validate_transition(JobState.VALIDATING, JobState.QUARANTINED)
    validate_transition(JobState.QUARANTINED, JobState.QUEUED)
    validate_transition(JobState.QUEUED, JobState.RUNNING)
    validate_transition(JobState.RUNNING, JobState.COMPLETED)


def test_invalid_job_transition_is_rejected():
    with pytest.raises(ValueError):
        validate_transition(JobState.CREATED, JobState.COMPLETED)


def test_terminal_states_are_explicit():
    assert is_terminal(JobState.COMPLETED)
    assert is_terminal(JobState.CANCELLED)
    assert not is_terminal(JobState.RUNNING)
