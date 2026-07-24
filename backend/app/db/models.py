"""Persistent Phase 2 scan, artifact, event, and immutable-result models."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ArtifactModel(Base):
    __tablename__ = "artifacts"

    artifact_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    zip_entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    total_uncompressed_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    jobs: Mapped[list["ScanJobModel"]] = relationship(back_populates="artifact")


class ScanJobModel(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_state_updated", "state", "updated_at"),
        Index("ix_scan_jobs_created_at", "created_at"),
    )

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    artifact_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("artifacts.artifact_id", ondelete="RESTRICT"), nullable=True, index=True
    )
    request_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_stage: Mapped[str] = mapped_column(String(128), default="created", nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    queue_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    execution_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    artifact: Mapped[ArtifactModel | None] = relationship(back_populates="jobs")
    events: Mapped[list["ScanEventModel"]] = relationship(
        back_populates="job", cascade="all, delete-orphan", order_by="ScanEventModel.sequence"
    )
    result: Mapped["ScanResultModel | None"] = relationship(back_populates="job", uselist=False)


class ScanEventModel(Base):
    __tablename__ = "scan_events"
    __table_args__ = (UniqueConstraint("scan_id", "sequence", name="uq_scan_event_sequence"),)

    event_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.scan_id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    previous_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    event_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    job: Mapped[ScanJobModel] = relationship(back_populates="events")


class ScanResultModel(Base):
    __tablename__ = "scan_results"

    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.scan_id", ondelete="RESTRICT"), primary_key=True
    )
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    result_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)
    immutable_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    job: Mapped[ScanJobModel] = relationship(back_populates="result")


@event.listens_for(ScanResultModel, "before_update")
def reject_scan_result_update(_mapper, _connection, _target) -> None:
    raise RuntimeError("Scan results are immutable; create a new scan result version instead of updating.")
