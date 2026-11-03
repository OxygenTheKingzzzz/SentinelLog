"""Relational schema for SentinelLog.

Milestone 1 writes log sources, ingestion jobs, templates, events, parse errors,
and audit rows. detection_rules, security_alerts, investigations, and
investigation_events exist so later milestones can land without a redesign.
They are not populated with synthetic detections.
"""

import uuid
from datetime import datetime, time

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
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
            "kind IN ('raw_log','template_csv','structured_import','structured_validate')",
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
        CheckConstraint("origin IN ('raw_log','structured_csv')", name="ck_log_events_origin"),
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
    """Reserved for a later milestone. Milestone 1 does not evaluate rules."""

    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    severity: Mapped[str | None] = mapped_column(String(32))
    logic: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )


class SecurityAlert(Base):
    """Reserved for a later milestone. Left empty on purpose."""

    __tablename__ = "security_alerts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("detection_rules.id", ondelete="SET NULL")
    )
    log_event_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("log_events.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="open", server_default=text("'open'")
    )
    details: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint("status IN ('open','closed')", name="ck_security_alerts_status"),
        Index("ix_security_alerts_status", "status"),
        Index("ix_security_alerts_log_event_id", "log_event_id"),
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
