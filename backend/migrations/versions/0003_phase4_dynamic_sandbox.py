"""Phase 4 isolated Android sandbox sessions and immutable events.

Revision ID: 0003_phase4
Revises: 0002_phase2
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_phase4"
down_revision = "0002_phase2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sandbox_sessions",
        sa.Column("session_id", sa.String(length=36), primary_key=True),
        sa.Column(
            "scan_id",
            sa.String(length=36),
            sa.ForeignKey("scan_jobs.scan_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("avd_name", sa.String(length=256), nullable=False),
        sa.Column("emulator_serial", sa.String(length=64)),
        sa.Column("network_mode", sa.String(length=32), nullable=False),
        sa.Column("instrumentation_mode", sa.String(length=32), nullable=False),
        sa.Column("policy_digest", sa.String(length=64), nullable=False),
        sa.Column("artifact_directory", sa.Text(), nullable=False),
        sa.Column("error_code", sa.String(length=128)),
        sa.Column("error_message", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("scan_id", name="uq_sandbox_session_scan_id"),
    )
    op.create_index("ix_sandbox_sessions_scan_id", "sandbox_sessions", ["scan_id"])
    op.create_index("ix_sandbox_sessions_state", "sandbox_sessions", ["state"])
    op.create_index("ix_sandbox_sessions_state_updated", "sandbox_sessions", ["state", "updated_at"])
    op.create_table(
        "sandbox_events",
        sa.Column("event_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "session_id",
            sa.String(length=36),
            sa.ForeignKey("sandbox_sessions.session_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=256), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("evidence_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("session_id", "sequence", name="uq_sandbox_event_sequence"),
    )
    op.create_index("ix_sandbox_events_session_id", "sandbox_events", ["session_id"])
    op.create_index("ix_sandbox_events_evidence_digest", "sandbox_events", ["evidence_digest"])


def downgrade() -> None:
    op.drop_table("sandbox_events")
    op.drop_table("sandbox_sessions")
