"""live file collectors

Revision ID: e7b1c4d09a52
Revises: d5f2a8c13e40
Create Date: 2026-11-03 08:50:00

Optional read-only file tails. Upgrade does not read or delete log events,
rule alerts, or anomaly scores. Existing sources become kind historical.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e7b1c4d09a52"
down_revision: str | Sequence[str] | None = "d5f2a8c13e40"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "log_sources",
        sa.Column(
            "kind",
            sa.String(length=32),
            server_default=sa.text("'historical'"),
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "ck_log_sources_kind",
        "log_sources",
        "kind IN ('historical','live_file')",
    )
    op.drop_constraint("ck_ingestion_jobs_kind", "ingestion_jobs", type_="check")
    op.create_check_constraint(
        "ck_ingestion_jobs_kind",
        "ingestion_jobs",
        "kind IN ('raw_log','template_csv','structured_import','structured_validate','live_file')",
    )
    op.drop_constraint("ck_log_events_origin", "log_events", type_="check")
    op.create_check_constraint(
        "ck_log_events_origin",
        "log_events",
        "origin IN ('raw_log','structured_csv','live_file')",
    )
    op.create_table(
        "live_collectors",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=16), server_default=sa.text("'file'"), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default=sa.text("'running'"), nullable=False
        ),
        sa.Column("device", sa.BigInteger(), nullable=True),
        sa.Column("inode", sa.BigInteger(), nullable=True),
        sa.Column("byte_offset", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("partial", sa.Text(), server_default=sa.text("''"), nullable=False),
        sa.Column("next_line_number", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("lines_read", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("lines_imported", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "duplicates_skipped", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("lines_errored", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("kind = 'file'", name="ck_live_collectors_kind"),
        sa.CheckConstraint(
            "status IN ('running','stopped','waiting','error')",
            name="ck_live_collectors_status",
        ),
        sa.CheckConstraint("byte_offset >= 0", name="ck_live_collectors_byte_offset"),
        sa.CheckConstraint("next_line_number >= 1", name="ck_live_collectors_next_line"),
        sa.CheckConstraint("lines_read >= 0", name="ck_live_collectors_lines_read"),
        sa.CheckConstraint("lines_imported >= 0", name="ck_live_collectors_lines_imported"),
        sa.CheckConstraint("duplicates_skipped >= 0", name="ck_live_collectors_duplicates"),
        sa.CheckConstraint("lines_errored >= 0", name="ck_live_collectors_lines_errored"),
        sa.CheckConstraint("length(partial) <= 8192", name="ck_live_collectors_partial"),
        sa.ForeignKeyConstraint(["job_id"], ["ingestion_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_id"], ["log_sources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_id", name="uq_live_collectors_source_id"),
    )
    op.create_index("ix_live_collectors_enabled", "live_collectors", ["enabled"], unique=False)
    op.create_table(
        "live_positions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("collector_id", sa.Uuid(), nullable=False),
        sa.Column("device", sa.BigInteger(), nullable=False),
        sa.Column("inode", sa.BigInteger(), nullable=False),
        sa.Column("byte_offset", sa.BigInteger(), nullable=False),
        sa.Column("line_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("byte_offset >= 0", name="ck_live_positions_byte_offset"),
        sa.CheckConstraint("line_sha256 ~ '^[0-9a-f]{64}$'", name="ck_live_positions_sha"),
        sa.ForeignKeyConstraint(["collector_id"], ["live_collectors.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("collector_id", "line_sha256", name="uq_live_positions_sha"),
    )
    op.create_index(
        "ix_live_positions_collector_id", "live_positions", ["collector_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_live_positions_collector_id", table_name="live_positions")
    op.drop_table("live_positions")
    op.drop_index("ix_live_collectors_enabled", table_name="live_collectors")
    op.drop_table("live_collectors")
    op.drop_constraint("ck_log_events_origin", "log_events", type_="check")
    op.create_check_constraint(
        "ck_log_events_origin",
        "log_events",
        "origin IN ('raw_log','structured_csv')",
    )
    op.drop_constraint("ck_ingestion_jobs_kind", "ingestion_jobs", type_="check")
    op.create_check_constraint(
        "ck_ingestion_jobs_kind",
        "ingestion_jobs",
        "kind IN ('raw_log','template_csv','structured_import','structured_validate')",
    )
    op.drop_constraint("ck_log_sources_kind", "log_sources", type_="check")
    op.drop_column("log_sources", "kind")
