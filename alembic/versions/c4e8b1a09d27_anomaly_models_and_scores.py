"""anomaly models and scores

Revision ID: c4e8b1a09d27
Revises: ed1cc76d8439
Create Date: 2026-11-03 08:20:00

Experimental anomaly models and per-window scores. These tables are not
security_alerts. Upgrade does not read or delete rule alerts.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c4e8b1a09d27"
down_revision: str | Sequence[str] | None = "ed1cc76d8439"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "anomaly_models",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.String(length=64), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("window_type", sa.String(length=16), nullable=False),
        sa.Column("train_fraction", sa.Double(), nullable=False),
        sa.Column("n_train", sa.Integer(), nullable=False),
        sa.Column("n_validation", sa.Integer(), nullable=False),
        sa.Column("baseline_z_threshold", sa.Double(), nullable=False),
        sa.Column("isolation_score_threshold", sa.Double(), nullable=False),
        sa.Column("feature_names", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("feature_medians", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("feature_mads", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("feature_scales", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("feature_scale_kinds", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("template_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("component_names", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("hyperparameters", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("validation_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("train_windows", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("validation_windows", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("dropped_features", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("artifact_path", sa.Text(), nullable=False),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("sklearn_version", sa.String(length=32), nullable=False),
        sa.Column("disclaimer", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("version >= 1", name="ck_anomaly_models_version"),
        sa.CheckConstraint("window_seconds >= 1", name="ck_anomaly_models_window_seconds"),
        sa.CheckConstraint("window_type = 'tumbling'", name="ck_anomaly_models_window_type"),
        sa.CheckConstraint("n_train >= 1", name="ck_anomaly_models_n_train"),
        sa.CheckConstraint("n_validation >= 1", name="ck_anomaly_models_n_validation"),
        sa.CheckConstraint(
            "train_fraction > 0 AND train_fraction < 1",
            name="ck_anomaly_models_train_fraction",
        ),
        sa.CheckConstraint(
            "baseline_z_threshold > 0",
            name="ck_anomaly_models_baseline_z_threshold",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(feature_names) = 'array'",
            name="ck_anomaly_models_feature_names_array",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(feature_medians) = 'object'",
            name="ck_anomaly_models_feature_medians_object",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(feature_mads) = 'object'",
            name="ck_anomaly_models_feature_mads_object",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(feature_scales) = 'object'",
            name="ck_anomaly_models_feature_scales_object",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(feature_scale_kinds) = 'object'",
            name="ck_anomaly_models_feature_scale_kinds_object",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(template_ids) = 'array'",
            name="ck_anomaly_models_template_ids_array",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(component_names) = 'array'",
            name="ck_anomaly_models_component_names_array",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(hyperparameters) = 'object'",
            name="ck_anomaly_models_hyperparameters_object",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(validation_summary) = 'object'",
            name="ck_anomaly_models_validation_summary_object",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(train_windows) = 'array'",
            name="ck_anomaly_models_train_windows_array",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(validation_windows) = 'array'",
            name="ck_anomaly_models_validation_windows_array",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(dropped_features) = 'array'",
            name="ck_anomaly_models_dropped_features_array",
        ),
        sa.CheckConstraint(
            "artifact_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_anomaly_models_sha",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("version", name="uq_anomaly_models_version"),
    )
    op.create_index(
        "ix_anomaly_models_created_at", "anomaly_models", ["created_at"], unique=False
    )
    op.create_table(
        "anomaly_scores",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("model_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("split_role", sa.String(length=32), nullable=False),
        sa.Column("features", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("isolation_score", sa.Double(), nullable=False),
        sa.Column("baseline_score", sa.Double(), nullable=False),
        sa.Column("flagged_isolation", sa.Boolean(), nullable=False),
        sa.Column("flagged_baseline", sa.Boolean(), nullable=False),
        sa.Column("explanation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("event_count >= 0", name="ck_anomaly_scores_event_count"),
        sa.CheckConstraint(
            "split_role IN ('train','validation','new')",
            name="ck_anomaly_scores_split_role",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(features) = 'object'",
            name="ck_anomaly_scores_features_object",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(explanation) = 'object'",
            name="ck_anomaly_scores_explanation_object",
        ),
        sa.ForeignKeyConstraint(
            ["model_id"],
            ["anomaly_models.id"],
            name="anomaly_scores_model_id_fkey",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["log_sources.id"],
            name="anomaly_scores_source_id_fkey",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "model_id",
            "source_id",
            "window_start",
            name="uq_anomaly_scores_window",
        ),
    )
    op.create_index("ix_anomaly_scores_model_id", "anomaly_scores", ["model_id"], unique=False)
    op.create_index("ix_anomaly_scores_source_id", "anomaly_scores", ["source_id"], unique=False)
    op.create_index(
        "ix_anomaly_scores_window_start", "anomaly_scores", ["window_start"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_anomaly_scores_window_start", table_name="anomaly_scores")
    op.drop_index("ix_anomaly_scores_source_id", table_name="anomaly_scores")
    op.drop_index("ix_anomaly_scores_model_id", table_name="anomaly_scores")
    op.drop_table("anomaly_scores")
    op.drop_index("ix_anomaly_models_created_at", table_name="anomaly_models")
    op.drop_table("anomaly_models")
