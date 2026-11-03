"""risk labels, models, and predictions

Revision ID: f3a91c2e8b17
Revises: e7b1c4d09a52
Create Date: 2026-11-03 11:20:00

Adds risk classification tables. Upgrade does not read or delete log events,
security alerts, or anomaly scores.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f3a91c2e8b17"
down_revision: str | Sequence[str] | None = "e7b1c4d09a52"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "risk_labels",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("log_event_id", sa.Uuid(), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("provenance", sa.String(length=32), nullable=False),
        sa.Column("reviewer", sa.String(length=200), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("rule_id", sa.Uuid(), nullable=True),
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
        sa.CheckConstraint(
            "risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')",
            name="ck_risk_labels_level",
        ),
        sa.CheckConstraint(
            "provenance IN ('verified_manual','verified_import','weak_rule')",
            name="ck_risk_labels_provenance",
        ),
        sa.ForeignKeyConstraint(["log_event_id"], ["log_events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("log_event_id", "provenance", name="uq_risk_labels_event_provenance"),
    )
    op.create_index("ix_risk_labels_log_event_id", "risk_labels", ["log_event_id"])
    op.create_index("ix_risk_labels_provenance", "risk_labels", ["provenance"])

    op.create_table(
        "risk_models",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.String(length=64), nullable=False),
        sa.Column("task", sa.String(length=32), nullable=False),
        sa.Column("dataset_name", sa.String(length=64), nullable=False),
        sa.Column("dataset_version", sa.String(length=128), nullable=False),
        sa.Column("label_provenance", sa.String(length=32), nullable=False),
        sa.Column("random_seed", sa.Integer(), nullable=False),
        sa.Column("n_train", sa.Integer(), nullable=False),
        sa.Column("n_test", sa.Integer(), nullable=False),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("metrics_status", sa.String(length=32), nullable=False),
        sa.Column("metrics_note", sa.Text(), nullable=False),
        sa.Column(
            "config",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("artifact_path", sa.Text(), nullable=False),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("sklearn_version", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("version >= 1", name="ck_risk_models_version"),
        sa.CheckConstraint(
            "algorithm IN ('isolation_forest','random_forest','tfidf_logreg')",
            name="ck_risk_models_algorithm",
        ),
        sa.CheckConstraint(
            "task IN ('multiclass_risk','binary_anomaly','unsupervised_band')",
            name="ck_risk_models_task",
        ),
        sa.CheckConstraint(
            "metrics_status IN ('evaluated','not_evaluated','weak_agreement_only')",
            name="ck_risk_models_metrics_status",
        ),
        sa.CheckConstraint("n_train >= 0", name="ck_risk_models_n_train"),
        sa.CheckConstraint("n_test >= 0", name="ck_risk_models_n_test"),
        sa.CheckConstraint(
            "metrics IS NULL OR jsonb_typeof(metrics) = 'object'",
            name="ck_risk_models_metrics_object",
        ),
        sa.CheckConstraint("jsonb_typeof(config) = 'object'", name="ck_risk_models_config_object"),
        sa.CheckConstraint("artifact_sha256 ~ '^[0-9a-f]{64}$'", name="ck_risk_models_sha"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("version", name="uq_risk_models_version"),
    )
    op.create_index("ix_risk_models_created_at", "risk_models", ["created_at"])
    op.create_index("ix_risk_models_dataset_name", "risk_models", ["dataset_name"])

    op.create_table(
        "risk_predictions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("model_id", sa.Uuid(), nullable=False),
        sa.Column("log_event_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("split_role", sa.String(length=16), nullable=False),
        sa.Column("predicted_risk", sa.String(length=16), nullable=False),
        sa.Column("class_confidence", sa.Double(), nullable=True),
        sa.Column("anomaly_score", sa.Double(), nullable=True),
        sa.Column("score_kind", sa.String(length=32), nullable=False),
        sa.Column("explanation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "split_role IN ('train','test','inference')",
            name="ck_risk_predictions_split",
        ),
        sa.CheckConstraint(
            "predicted_risk IN ('LOW','MEDIUM','HIGH','CRITICAL')",
            name="ck_risk_predictions_level",
        ),
        sa.CheckConstraint(
            "class_confidence IS NULL OR (class_confidence >= 0 AND class_confidence <= 1)",
            name="ck_risk_predictions_confidence",
        ),
        sa.CheckConstraint(
            "score_kind IN ('class_probability','anomaly_score','both')",
            name="ck_risk_predictions_score_kind",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(explanation) = 'object'",
            name="ck_risk_predictions_explanation",
        ),
        sa.ForeignKeyConstraint(["log_event_id"], ["log_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["model_id"], ["risk_models.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_id"], ["log_sources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("model_id", "log_event_id", name="uq_risk_predictions_model_event"),
    )
    op.create_index("ix_risk_predictions_log_event_id", "risk_predictions", ["log_event_id"])
    op.create_index("ix_risk_predictions_model_id", "risk_predictions", ["model_id"])
    op.create_index("ix_risk_predictions_source_id", "risk_predictions", ["source_id"])


def downgrade() -> None:
    op.drop_index("ix_risk_predictions_source_id", table_name="risk_predictions")
    op.drop_index("ix_risk_predictions_model_id", table_name="risk_predictions")
    op.drop_index("ix_risk_predictions_log_event_id", table_name="risk_predictions")
    op.drop_table("risk_predictions")
    op.drop_index("ix_risk_models_dataset_name", table_name="risk_models")
    op.drop_index("ix_risk_models_created_at", table_name="risk_models")
    op.drop_table("risk_models")
    op.drop_index("ix_risk_labels_provenance", table_name="risk_labels")
    op.drop_index("ix_risk_labels_log_event_id", table_name="risk_labels")
    op.drop_table("risk_labels")
