"""Relational schema for SentinelLog.

Milestone 1 writes log sources, ingestion jobs, templates, events, parse errors,
and audit rows. Milestone 2 evaluates detection_rules and writes security_alerts
from stored log_events. Milestone 3 writes anomaly_models and anomaly_scores.
Those scores are not rule alerts and are not ground truth. Investigations group stored evidence.
"""

import uuid
from datetime import datetime, time

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Double,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Time,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sentinellog.clock import utcnow


class Base(DeclarativeBase):
    pass


class LogSource(Base):
    __tablename__ = "log_sources"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    hostname: Mapped[str | None] = mapped_column(Text)
    source_year: Mapped[int | None] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="historical", server_default=text("'historical'")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint(
            "source_year IS NULL OR (source_year >= 1970 AND source_year <= 2100)",
            name="ck_log_sources_year",
        ),
        CheckConstraint("kind IN ('historical','live_file')", name="ck_log_sources_kind"),
    )


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("log_sources.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    lines_total: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    lines_parsed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    lines_errored: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    duplicates_skipped: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    conflicts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    stats: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint(
            "kind IN ('raw_log','template_csv','structured_import',"
            "'structured_validate','live_file')",
            name="ck_ingestion_jobs_kind",
        ),
        CheckConstraint(
            "status IN ('pending','running','completed','failed')",
            name="ck_ingestion_jobs_status",
        ),
        CheckConstraint("lines_total >= 0", name="ck_ingestion_jobs_lines_total"),
        CheckConstraint("lines_parsed >= 0", name="ck_ingestion_jobs_lines_parsed"),
        CheckConstraint("lines_errored >= 0", name="ck_ingestion_jobs_lines_errored"),
        CheckConstraint("duplicates_skipped >= 0", name="ck_ingestion_jobs_duplicates"),
        CheckConstraint("conflicts >= 0", name="ck_ingestion_jobs_conflicts"),
        CheckConstraint("file_sha256 ~ '^[0-9a-f]{64}$'", name="ck_ingestion_jobs_sha"),
        Index("ix_ingestion_jobs_source_id", "source_id"),
        Index("ix_ingestion_jobs_status", "status"),
    )


class EventTemplate(Base):
    __tablename__ = "event_templates"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    event_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    template: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )


class LogEvent(Base):
    __tablename__ = "log_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("log_sources.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("ingestion_jobs.id", ondelete="RESTRICT"), nullable=False
    )
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_line: Mapped[str] = mapped_column(Text, nullable=False)
    raw_line_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(160), nullable=False)
    origin: Mapped[str] = mapped_column(String(32), nullable=False)
    month: Mapped[str] = mapped_column(String(3), nullable=False)
    day: Mapped[int] = mapped_column(Integer, nullable=False)
    time_of_day: Mapped[time] = mapped_column(Time, nullable=False)
    event_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hostname: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment=(
            "Syslog hostname. The Linux_2k CSV column Level is stored here and is not a severity."
        ),
    )
    component: Mapped[str] = mapped_column(Text, nullable=False)
    pid: Mapped[int | None] = mapped_column(Integer)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    event_id: Mapped[str | None] = mapped_column(String(32))
    event_template: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    username: Mapped[str | None] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        UniqueConstraint("dedup_key", name="uq_log_events_dedup_key"),
        UniqueConstraint("source_id", "line_number", name="uq_log_events_source_line"),
        CheckConstraint("line_number > 0", name="ck_log_events_line_number"),
        CheckConstraint(
            "month IN ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec')",
            name="ck_log_events_month",
        ),
        CheckConstraint("day >= 1 AND day <= 31", name="ck_log_events_day"),
        CheckConstraint("length(hostname) > 0", name="ck_log_events_hostname"),
        CheckConstraint("length(component) > 0", name="ck_log_events_component"),
        CheckConstraint("length(content) > 0", name="ck_log_events_content"),
        CheckConstraint("pid IS NULL OR pid >= 0", name="ck_log_events_pid"),
        CheckConstraint("raw_line_sha256 ~ '^[0-9a-f]{64}$'", name="ck_log_events_sha"),
        CheckConstraint(
            "origin IN ('raw_log','structured_csv','live_file')",
            name="ck_log_events_origin",
        ),
        Index("ix_log_events_component", "component"),
        Index("ix_log_events_event_id", "event_id"),
        Index("ix_log_events_event_timestamp", "event_timestamp"),
        Index("ix_log_events_hostname", "hostname"),
        Index("ix_log_events_source_component", "source_id", "component"),
        Index("ix_log_events_source_event", "source_id", "event_id"),
        Index("ix_log_events_source_timestamp", "source_id", "event_timestamp"),
        Index("ix_log_events_job_id", "job_id"),
        Index(
            "ix_log_events_content_trgm",
            "content",
            postgresql_using="gin",
            postgresql_ops={"content": "gin_trgm_ops"},
        ),
    )


class IngestionError(Base):
    __tablename__ = "ingestion_errors"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("ingestion_jobs.id", ondelete="CASCADE"), nullable=False
    )
    line_number: Mapped[int | None] = mapped_column(Integer)
    error_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    raw_line: Mapped[str | None] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint(
            "error_kind IN ('parse','conflict','mismatch','template')",
            name="ck_ingestion_errors_kind",
        ),
        Index("ix_ingestion_errors_job_id", "job_id"),
    )


class DetectionRule(Base):
    """Configurable threshold rule. `version` increments when the definition changes."""

    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    severity: Mapped[str | None] = mapped_column(String(32))
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    logic: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint("version >= 1", name="ck_detection_rules_version"),
        CheckConstraint(
            "severity IS NULL OR severity IN ('low','medium','high','critical')",
            name="ck_detection_rules_severity",
        ),
    )


class SecurityAlert(Base):
    """One rule finding. Severity is analyst priority, not a verified incident outcome."""

    __tablename__ = "security_alerts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("detection_rules.id", ondelete="RESTRICT"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("log_sources.id", ondelete="CASCADE"), nullable=False
    )
    rule_version: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="open", server_default=text("'open'")
    )
    source_address: Mapped[str | None] = mapped_column(String(256))
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    window_type: Mapped[str] = mapped_column(String(16), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_ids: Mapped[list] = mapped_column(JSONB, nullable=False)
    line_numbers: Mapped[list] = mapped_column(JSONB, nullable=False)
    group_value: Mapped[str] = mapped_column(String(256), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(700), nullable=False)
    details: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        UniqueConstraint("dedup_key", name="uq_security_alerts_dedup_key"),
        CheckConstraint(
            "status IN ('open','investigating','resolved','false_positive')",
            name="ck_security_alerts_status",
        ),
        CheckConstraint(
            "severity IN ('low','medium','high','critical')",
            name="ck_security_alerts_severity",
        ),
        CheckConstraint(
            "window_type IN ('sliding','tumbling')",
            name="ck_security_alerts_window_type",
        ),
        CheckConstraint("threshold >= 1", name="ck_security_alerts_threshold"),
        CheckConstraint("window_seconds >= 1", name="ck_security_alerts_window_seconds"),
        CheckConstraint("rule_version >= 1", name="ck_security_alerts_rule_version"),
        CheckConstraint(
            "jsonb_typeof(event_ids) = 'array'",
            name="ck_security_alerts_event_ids_array",
        ),
        CheckConstraint(
            "jsonb_typeof(line_numbers) = 'array'",
            name="ck_security_alerts_line_numbers_array",
        ),
        Index("ix_security_alerts_rule_id", "rule_id"),
        Index("ix_security_alerts_severity", "severity"),
        Index("ix_security_alerts_source_id", "source_id"),
        Index("ix_security_alerts_status", "status"),
    )


class AlertNote(Base):
    """Analyst note recorded with a security alert status transition."""

    __tablename__ = "alert_notes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False
    )
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False)
    from_status: Mapped[str] = mapped_column(String(32), nullable=False)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint(
            "from_status IN ('open','investigating','resolved','false_positive')",
            name="ck_alert_notes_from_status",
        ),
        CheckConstraint(
            "to_status IN ('open','investigating','resolved','false_positive')",
            name="ck_alert_notes_to_status",
        ),
        CheckConstraint("length(note) > 0", name="ck_alert_notes_note"),
        Index("ix_alert_notes_alert_id", "alert_id"),
    )


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="open", server_default=text("'open'")
    )
    summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint("status IN ('open','closed')", name="ck_investigations_status"),
    )


class InvestigationEvent(Base):
    __tablename__ = "investigation_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    log_event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("log_events.id", ondelete="CASCADE"), nullable=False
    )
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        UniqueConstraint("investigation_id", "log_event_id", name="uq_investigation_events_pair"),
        Index("ix_investigation_events_investigation_id", "investigation_id"),
        Index("ix_investigation_events_log_event_id", "log_event_id"),
    )


class InvestigationAlert(Base):
    """Rule alert attached to an investigation. The alert itself stays in security_alerts."""

    __tablename__ = "investigation_alerts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        UniqueConstraint("investigation_id", "alert_id", name="uq_investigation_alerts_pair"),
        Index("ix_investigation_alerts_investigation_id", "investigation_id"),
        Index("ix_investigation_alerts_alert_id", "alert_id"),
    )


class InvestigationNote(Base):
    """Analyst note on an investigation. This is not a rule finding."""

    __tablename__ = "investigation_notes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint("length(body) > 0", name="ck_investigation_notes_body"),
        Index("ix_investigation_notes_investigation_id", "investigation_id"),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_action", "action"),
    )


class AnomalyModel(Base):
    """A trained anomaly model. Scores from this row are not security_alerts."""

    __tablename__ = "anomaly_models"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    window_type: Mapped[str] = mapped_column(String(16), nullable=False)
    train_fraction: Mapped[float] = mapped_column(Double, nullable=False)
    n_train: Mapped[int] = mapped_column(Integer, nullable=False)
    n_validation: Mapped[int] = mapped_column(Integer, nullable=False)
    baseline_z_threshold: Mapped[float] = mapped_column(Double, nullable=False)
    isolation_score_threshold: Mapped[float] = mapped_column(Double, nullable=False)
    feature_names: Mapped[list] = mapped_column(JSONB, nullable=False)
    feature_medians: Mapped[dict] = mapped_column(JSONB, nullable=False)
    feature_mads: Mapped[dict] = mapped_column(JSONB, nullable=False)
    feature_scales: Mapped[dict] = mapped_column(JSONB, nullable=False)
    feature_scale_kinds: Mapped[dict] = mapped_column(JSONB, nullable=False)
    template_ids: Mapped[list] = mapped_column(JSONB, nullable=False)
    component_names: Mapped[list] = mapped_column(JSONB, nullable=False)
    hyperparameters: Mapped[dict] = mapped_column(JSONB, nullable=False)
    validation_summary: Mapped[dict] = mapped_column(JSONB, nullable=False)
    train_windows: Mapped[list] = mapped_column(JSONB, nullable=False)
    validation_windows: Mapped[list] = mapped_column(JSONB, nullable=False)
    dropped_features: Mapped[list] = mapped_column(JSONB, nullable=False)
    artifact_path: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sklearn_version: Mapped[str] = mapped_column(String(32), nullable=False)
    disclaimer: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        UniqueConstraint("version", name="uq_anomaly_models_version"),
        CheckConstraint("version >= 1", name="ck_anomaly_models_version"),
        CheckConstraint("window_seconds >= 1", name="ck_anomaly_models_window_seconds"),
        CheckConstraint("window_type = 'tumbling'", name="ck_anomaly_models_window_type"),
        CheckConstraint("n_train >= 1", name="ck_anomaly_models_n_train"),
        CheckConstraint("n_validation >= 1", name="ck_anomaly_models_n_validation"),
        CheckConstraint(
            "train_fraction > 0 AND train_fraction < 1",
            name="ck_anomaly_models_train_fraction",
        ),
        CheckConstraint(
            "baseline_z_threshold > 0",
            name="ck_anomaly_models_baseline_z_threshold",
        ),
        CheckConstraint(
            "jsonb_typeof(feature_names) = 'array'",
            name="ck_anomaly_models_feature_names_array",
        ),
        CheckConstraint(
            "jsonb_typeof(feature_medians) = 'object'",
            name="ck_anomaly_models_feature_medians_object",
        ),
        CheckConstraint(
            "jsonb_typeof(feature_mads) = 'object'",
            name="ck_anomaly_models_feature_mads_object",
        ),
        CheckConstraint(
            "jsonb_typeof(feature_scales) = 'object'",
            name="ck_anomaly_models_feature_scales_object",
        ),
        CheckConstraint(
            "jsonb_typeof(feature_scale_kinds) = 'object'",
            name="ck_anomaly_models_feature_scale_kinds_object",
        ),
        CheckConstraint(
            "jsonb_typeof(template_ids) = 'array'",
            name="ck_anomaly_models_template_ids_array",
        ),
        CheckConstraint(
            "jsonb_typeof(component_names) = 'array'",
            name="ck_anomaly_models_component_names_array",
        ),
        CheckConstraint(
            "jsonb_typeof(hyperparameters) = 'object'",
            name="ck_anomaly_models_hyperparameters_object",
        ),
        CheckConstraint(
            "jsonb_typeof(validation_summary) = 'object'",
            name="ck_anomaly_models_validation_summary_object",
        ),
        CheckConstraint(
            "jsonb_typeof(train_windows) = 'array'",
            name="ck_anomaly_models_train_windows_array",
        ),
        CheckConstraint(
            "jsonb_typeof(validation_windows) = 'array'",
            name="ck_anomaly_models_validation_windows_array",
        ),
        CheckConstraint(
            "jsonb_typeof(dropped_features) = 'array'",
            name="ck_anomaly_models_dropped_features_array",
        ),
        CheckConstraint(
            "artifact_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_anomaly_models_sha",
        ),
        Index("ix_anomaly_models_created_at", "created_at"),
    )


class AnomalyScore(Base):
    """One window scored by an anomaly model. This is not a security_alerts row."""

    __tablename__ = "anomaly_scores"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    model_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("anomaly_models.id", ondelete="CASCADE"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("log_sources.id", ondelete="CASCADE"), nullable=False
    )
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    split_role: Mapped[str] = mapped_column(String(32), nullable=False)
    features: Mapped[dict] = mapped_column(JSONB, nullable=False)
    isolation_score: Mapped[float] = mapped_column(Double, nullable=False)
    baseline_score: Mapped[float] = mapped_column(Double, nullable=False)
    flagged_isolation: Mapped[bool] = mapped_column(Boolean, nullable=False)
    flagged_baseline: Mapped[bool] = mapped_column(Boolean, nullable=False)
    explanation: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        UniqueConstraint("model_id", "source_id", "window_start", name="uq_anomaly_scores_window"),
        CheckConstraint("event_count >= 0", name="ck_anomaly_scores_event_count"),
        CheckConstraint(
            "split_role IN ('train','validation','new')",
            name="ck_anomaly_scores_split_role",
        ),
        CheckConstraint(
            "jsonb_typeof(features) = 'object'",
            name="ck_anomaly_scores_features_object",
        ),
        CheckConstraint(
            "jsonb_typeof(explanation) = 'object'",
            name="ck_anomaly_scores_explanation_object",
        ),
        Index("ix_anomaly_scores_model_id", "model_id"),
        Index("ix_anomaly_scores_source_id", "source_id"),
        Index("ix_anomaly_scores_window_start", "window_start"),
    )


class LiveCollector(Base):
    """Read-only tail of one explicitly authorized file. Not a linux-2k import."""

    __tablename__ = "live_collectors"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("log_sources.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("ingestion_jobs.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default="file", server_default=text("'file'")
    )
    path: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="running", server_default=text("'running'")
    )
    device: Mapped[int | None] = mapped_column(BigInteger)
    inode: Mapped[int | None] = mapped_column(BigInteger)
    byte_offset: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    partial: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=text("''")
    )
    next_line_number: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    lines_read: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    lines_imported: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    duplicates_skipped: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    lines_errored: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    last_error: Mapped[str | None] = mapped_column(Text)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        UniqueConstraint("source_id", name="uq_live_collectors_source_id"),
        CheckConstraint("kind = 'file'", name="ck_live_collectors_kind"),
        CheckConstraint(
            "status IN ('running','stopped','waiting','error')",
            name="ck_live_collectors_status",
        ),
        CheckConstraint("byte_offset >= 0", name="ck_live_collectors_byte_offset"),
        CheckConstraint("next_line_number >= 1", name="ck_live_collectors_next_line"),
        CheckConstraint("lines_read >= 0", name="ck_live_collectors_lines_read"),
        CheckConstraint("lines_imported >= 0", name="ck_live_collectors_lines_imported"),
        CheckConstraint("duplicates_skipped >= 0", name="ck_live_collectors_duplicates"),
        CheckConstraint("lines_errored >= 0", name="ck_live_collectors_lines_errored"),
        CheckConstraint("length(partial) <= 8192", name="ck_live_collectors_partial"),
        Index("ix_live_collectors_enabled", "enabled"),
    )


class LivePosition(Base):
    """A line already consumed from an authorized file. Replay of that hash is a duplicate."""

    __tablename__ = "live_positions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    collector_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("live_collectors.id", ondelete="CASCADE"), nullable=False
    )
    device: Mapped[int] = mapped_column(BigInteger, nullable=False)
    inode: Mapped[int] = mapped_column(BigInteger, nullable=False)
    byte_offset: Mapped[int] = mapped_column(BigInteger, nullable=False)
    line_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        UniqueConstraint("collector_id", "line_sha256", name="uq_live_positions_sha"),
        CheckConstraint("byte_offset >= 0", name="ck_live_positions_byte_offset"),
        CheckConstraint("line_sha256 ~ '^[0-9a-f]{64}$'", name="ck_live_positions_sha"),
        Index("ix_live_positions_collector_id", "collector_id"),
    )
