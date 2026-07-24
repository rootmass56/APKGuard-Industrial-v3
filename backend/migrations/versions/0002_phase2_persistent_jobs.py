"""Phase 2 persistent jobs and immutable results.

Revision ID: 0002_phase2
Revises: None
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_phase2"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifacts",
        sa.Column("artifact_id", sa.String(length=36), primary_key=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("storage_path", sa.Text(), nullable=False),
        sa.Column("original_filename", sa.Text(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("zip_entry_count", sa.Integer(), nullable=False),
        sa.Column("total_uncompressed_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("sha256"),
    )
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"], unique=True)
    op.create_table(
        "scan_jobs",
        sa.Column("scan_id", sa.String(length=36), primary_key=True),
        sa.Column("artifact_id", sa.String(length=36), sa.ForeignKey("artifacts.artifact_id", ondelete="RESTRICT")),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column("correlation_id", sa.String(length=128), nullable=False),
        sa.Column("original_filename", sa.Text(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("current_stage", sa.String(length=128), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("queue_backend", sa.String(length=32), nullable=False),
        sa.Column("execution_mode", sa.String(length=32), nullable=False),
        sa.Column("error_code", sa.String(length=128)),
        sa.Column("error_message", sa.Text()),
        sa.Column("result_digest", sa.String(length=64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_scan_jobs_artifact_id", "scan_jobs", ["artifact_id"])
    op.create_index("ix_scan_jobs_request_id", "scan_jobs", ["request_id"])
    op.create_index("ix_scan_jobs_correlation_id", "scan_jobs", ["correlation_id"])
    op.create_index("ix_scan_jobs_state", "scan_jobs", ["state"])
    op.create_index("ix_scan_jobs_state_updated", "scan_jobs", ["state", "updated_at"])
    op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])
    op.create_table(
        "scan_events",
        sa.Column("event_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scan_jobs.scan_id", ondelete="CASCADE"), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("previous_state", sa.String(length=32)),
        sa.Column("new_state", sa.String(length=32)),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("event_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scan_id", "sequence", name="uq_scan_event_sequence"),
    )
    op.create_index("ix_scan_events_scan_id", "scan_events", ["scan_id"])
    op.create_table(
        "scan_results",
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scan_jobs.scan_id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("result_digest", sa.String(length=64), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("immutable_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_results_result_digest", "scan_results", ["result_digest"])


def downgrade() -> None:
    op.drop_table("scan_results")
    op.drop_table("scan_events")
    op.drop_table("scan_jobs")
    op.drop_table("artifacts")
