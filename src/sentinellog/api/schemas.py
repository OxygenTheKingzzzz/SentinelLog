import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from sentinellog.models import LogEvent, LogSource


class SourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    source_year: int | None = Field(default=None, ge=1970, le=2100)


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    hostname: str | None
    source_year: int | None
    kind: str
    created_at: datetime
    updated_at: datetime


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    kind: str
    filename: str
    status: str
    file_size_bytes: int
    file_sha256: str
    lines_total: int
    lines_parsed: int
    lines_errored: int
    duplicates_skipped: int
    conflicts: int
    stats: dict
    error_message: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class EventOut(BaseModel):
    id: uuid.UUID
    source_id: uuid.UUID
    job_id: uuid.UUID
    line_number: int
    raw_line: str
    raw_line_sha256: str
    dedup_key: str
    origin: str
    month: str
    day: int
    time_of_day: str
    event_timestamp: datetime | None
    hostname: str
    component: str
    pid: int | None
    content: str
    event_id: str | None
    event_template: str | None
    source_ip: str | None
    username: str | None


class EventPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[EventOut]


class ErrorOut(BaseModel):
    line_number: int | None
    error_kind: str
    message: str
    raw_line: str | None


class TemplateOut(BaseModel):
    event_id: str
    template: str


def source_out(source: LogSource) -> SourceOut:
    return SourceOut.model_validate(source)


def event_out(event: LogEvent) -> EventOut:
    return EventOut(
        id=event.id,
        source_id=event.source_id,
        job_id=event.job_id,
        line_number=event.line_number,
        raw_line=event.raw_line,
        raw_line_sha256=event.raw_line_sha256,
        dedup_key=event.dedup_key,
        origin=event.origin,
        month=event.month,
        day=event.day,
        time_of_day=event.time_of_day.strftime("%H:%M:%S"),
        event_timestamp=event.event_timestamp,
        hostname=event.hostname,
        component=event.component,
        pid=event.pid,
        content=event.content,
        event_id=event.event_id,
        event_template=event.event_template,
        source_ip=event.source_ip,
        username=event.username,
    )
