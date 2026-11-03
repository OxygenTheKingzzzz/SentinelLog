"""investigation alerts and notes

Revision ID: d5f2a8c13e40
Revises: c4e8b1a09d27
Create Date: 2026-11-03 08:40:00

Links stored security alerts and analyst notes to investigations.
Upgrade does not read or delete log events, rule alerts, or anomaly scores.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d5f2a8c13e40"
down_revision: str | Sequence[str] | None = "c4e8b1a09d27"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "investigation_alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "alert_id", name="uq_investigation_alerts_pair"),
    )
    op.create_index(
        "ix_investigation_alerts_alert_id",
        "investigation_alerts",
        ["alert_id"],
        unique=False,
    )
    op.create_index(
        "ix_investigation_alerts_investigation_id",
        "investigation_alerts",
        ["investigation_id"],
        unique=False,
    )
    op.create_table(
        "investigation_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("length(body) > 0", name="ck_investigation_notes_body"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_investigation_notes_investigation_id",
        "investigation_notes",
        ["investigation_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_investigation_notes_investigation_id", table_name="investigation_notes")
    op.drop_table("investigation_notes")
    op.drop_index(
        "ix_investigation_alerts_investigation_id", table_name="investigation_alerts"
    )
    op.drop_index("ix_investigation_alerts_alert_id", table_name="investigation_alerts")
    op.drop_table("investigation_alerts")
