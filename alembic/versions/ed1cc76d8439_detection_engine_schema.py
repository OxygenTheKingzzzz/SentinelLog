"""detection engine schema

Revision ID: ed1cc76d8439
Revises: 6a757cd7ca97
Create Date: 2026-11-03 07:57:30.876577

Adds rule versions, alert evidence, the open/investigating/resolved/false_positive
lifecycle, and analyst notes. security_alerts was unused in milestone 1, so the
new required columns are added directly. Upgrade refuses if that table already
has rows.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "ed1cc76d8439"
down_revision: Union[str, Sequence[str], None] = "6a757cd7ca97"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    existing = bind.execute(sa.text("SELECT COUNT(*) FROM security_alerts")).scalar_one()
    if existing:
        raise RuntimeError("security_alerts must be empty to upgrade the detection schema")

    op.add_column(
        "detection_rules",
        sa.Column("version", sa.Integer(), server_default=sa.text("1"), nullable=False),
    )
    op.create_check_constraint(
        "ck_detection_rules_version",
        "detection_rules",
        "version >= 1",
    )
    op.create_check_constraint(
        "ck_detection_rules_severity",
        "detection_rules",
        "severity IS NULL OR severity IN ('low','medium','high','critical')",
    )

    op.drop_constraint("ck_security_alerts_status", "security_alerts", type_="check")
    op.drop_index("ix_security_alerts_log_event_id", table_name="security_alerts")
    op.drop_constraint("security_alerts_log_event_id_fkey", "security_alerts", type_="foreignkey")
    op.drop_column("security_alerts", "log_event_id")
    op.drop_constraint("security_alerts_rule_id_fkey", "security_alerts", type_="foreignkey")
    op.alter_column("security_alerts", "rule_id", existing_type=sa.Uuid(), nullable=False)
    op.alter_column("security_alerts", "severity", existing_type=sa.String(32), nullable=False)
    op.create_foreign_key(
        "security_alerts_rule_id_fkey",
        "security_alerts",
        "detection_rules",
        ["rule_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    op.add_column("security_alerts", sa.Column("source_id", sa.Uuid(), nullable=False))
    op.add_column("security_alerts", sa.Column("rule_version", sa.Integer(), nullable=False))
    op.add_column("security_alerts", sa.Column("source_address", sa.String(256), nullable=True))
    op.add_column("security_alerts", sa.Column("explanation", sa.Text(), nullable=False))
    op.add_column("security_alerts", sa.Column("threshold", sa.Integer(), nullable=False))
    op.add_column("security_alerts", sa.Column("window_seconds", sa.Integer(), nullable=False))
    op.add_column("security_alerts", sa.Column("window_type", sa.String(16), nullable=False))
    op.add_column(
        "security_alerts",
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column(
        "security_alerts",
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column(
        "security_alerts",
        sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column(
        "security_alerts",
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column(
        "security_alerts",
        sa.Column("event_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    )
    op.add_column(
        "security_alerts",
        sa.Column("line_numbers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    )
    op.add_column("security_alerts", sa.Column("group_value", sa.String(256), nullable=False))
    op.add_column("security_alerts", sa.Column("dedup_key", sa.String(700), nullable=False))
    op.add_column(
        "security_alerts",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_foreign_key(
        "security_alerts_source_id_fkey",
        "security_alerts",
        "log_sources",
        ["source_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_check_constraint(
        "ck_security_alerts_status",
        "security_alerts",
        "status IN ('open','investigating','resolved','false_positive')",
    )
    op.create_check_constraint(
        "ck_security_alerts_severity",
        "security_alerts",
        "severity IN ('low','medium','high','critical')",
    )
    op.create_check_constraint(
        "ck_security_alerts_window_type",
        "security_alerts",
        "window_type IN ('sliding','tumbling')",
    )
    op.create_check_constraint(
        "ck_security_alerts_threshold",
        "security_alerts",
        "threshold >= 1",
    )
    op.create_check_constraint(
        "ck_security_alerts_window_seconds",
        "security_alerts",
        "window_seconds >= 1",
    )
    op.create_check_constraint(
        "ck_security_alerts_rule_version",
        "security_alerts",
        "rule_version >= 1",
    )
    op.create_check_constraint(
        "ck_security_alerts_event_ids_array",
        "security_alerts",
        "jsonb_typeof(event_ids) = 'array'",
    )
    op.create_check_constraint(
        "ck_security_alerts_line_numbers_array",
        "security_alerts",
        "jsonb_typeof(line_numbers) = 'array'",
    )
    op.create_index("ix_security_alerts_rule_id", "security_alerts", ["rule_id"], unique=False)
    op.create_index("ix_security_alerts_severity", "security_alerts", ["severity"], unique=False)
    op.create_index("ix_security_alerts_source_id", "security_alerts", ["source_id"], unique=False)
    op.create_unique_constraint("uq_security_alerts_dedup_key", "security_alerts", ["dedup_key"])

    op.create_table(
        "alert_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("from_status", sa.String(32), nullable=False),
        sa.Column("to_status", sa.String(32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "from_status IN ('open','investigating','resolved','false_positive')",
            name="ck_alert_notes_from_status",
        ),
        sa.CheckConstraint(
            "to_status IN ('open','investigating','resolved','false_positive')",
            name="ck_alert_notes_to_status",
        ),
        sa.CheckConstraint("length(note) > 0", name="ck_alert_notes_note"),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["security_alerts.id"],
            ondelete="CASCADE",
            name="alert_notes_alert_id_fkey",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_notes_alert_id", "alert_notes", ["alert_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_alert_notes_alert_id", table_name="alert_notes")
    op.drop_table("alert_notes")
    op.drop_constraint("uq_security_alerts_dedup_key", "security_alerts", type_="unique")
    op.drop_index("ix_security_alerts_source_id", table_name="security_alerts")
    op.drop_index("ix_security_alerts_severity", table_name="security_alerts")
    op.drop_index("ix_security_alerts_rule_id", table_name="security_alerts")
    for name in (
        "ck_security_alerts_line_numbers_array",
        "ck_security_alerts_event_ids_array",
        "ck_security_alerts_rule_version",
        "ck_security_alerts_window_seconds",
        "ck_security_alerts_threshold",
        "ck_security_alerts_window_type",
        "ck_security_alerts_severity",
        "ck_security_alerts_status",
    ):
        op.drop_constraint(name, "security_alerts", type_="check")
    op.drop_constraint("security_alerts_source_id_fkey", "security_alerts", type_="foreignkey")
    op.drop_column("security_alerts", "updated_at")
    op.drop_column("security_alerts", "dedup_key")
    op.drop_column("security_alerts", "group_value")
    op.drop_column("security_alerts", "line_numbers")
    op.drop_column("security_alerts", "event_ids")
    op.drop_column("security_alerts", "last_event_at")
    op.drop_column("security_alerts", "first_event_at")
    op.drop_column("security_alerts", "window_end")
    op.drop_column("security_alerts", "window_start")
    op.drop_column("security_alerts", "window_type")
    op.drop_column("security_alerts", "window_seconds")
    op.drop_column("security_alerts", "threshold")
    op.drop_column("security_alerts", "explanation")
    op.drop_column("security_alerts", "source_address")
    op.drop_column("security_alerts", "rule_version")
    op.drop_column("security_alerts", "source_id")
    op.drop_constraint("security_alerts_rule_id_fkey", "security_alerts", type_="foreignkey")
    op.alter_column("security_alerts", "severity", existing_type=sa.String(32), nullable=True)
    op.alter_column("security_alerts", "rule_id", existing_type=sa.Uuid(), nullable=True)
    op.add_column("security_alerts", sa.Column("log_event_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "security_alerts_rule_id_fkey",
        "security_alerts",
        "detection_rules",
        ["rule_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "security_alerts_log_event_id_fkey",
        "security_alerts",
        "log_events",
        ["log_event_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_security_alerts_log_event_id", "security_alerts", ["log_event_id"], unique=False
    )
    op.create_check_constraint(
        "ck_security_alerts_status",
        "security_alerts",
        "status IN ('open','closed')",
    )
    op.drop_constraint("ck_detection_rules_severity", "detection_rules", type_="check")
    op.drop_constraint("ck_detection_rules_version", "detection_rules", type_="check")
    op.drop_column("detection_rules", "version")
