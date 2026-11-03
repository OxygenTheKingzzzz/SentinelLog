"""Deterministic hourly features from stored log events.

The inputs are log_events columns and the event_templates catalog. Rule alerts,
alert status, and any label are not read. A feature is omitted only when a
column it needs is absent from log_events.
"""

import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from sentinellog.ml.constants import (
    AUTH_FAILURE_EVENT_IDS,
    FTP_CONNECTION_EVENT_ID,
    PRIVILEGED_USERNAMES,
    SCALAR_FEATURES,
    SERVICE_ERROR_EVENT_ID,
    WINDOW_SECONDS,
)
from sentinellog.models import EventTemplate, LogEvent

_RHOST = re.compile(r"rhost=(\S+)")
_TEMPLATE_ID = re.compile(r"E(\d+)$")


@dataclass
class RawWindow:
    source_id: UUID
    window_start: datetime
    window_end: datetime
    event_count: int = 0
    failed_auth_count: int = 0
    source_hosts: set[str] = field(default_factory=set)
    usernames: set[str] = field(default_factory=set)
    template_counts: dict[str, int] = field(default_factory=dict)
    component_counts: dict[str, int] = field(default_factory=dict)
    privileged_attempt_count: int = 0
    ftp_connection_count: int = 0
    service_error_count: int = 0
    unmatched_templates: int = 0


@dataclass(frozen=True)
class FeatureSchema:
    feature_names: tuple[str, ...]
    template_ids: tuple[str, ...]
    component_names: tuple[str, ...]
    dropped_features: tuple[dict[str, object], ...]


def log_event_columns(session: Session) -> set[str]:
    return {column["name"] for column in inspect(session.get_bind()).get_columns("log_events")}


def dropped_for_columns(columns: set[str]) -> list[dict[str, object]]:
    dropped: list[dict[str, object]] = []
    for name, required in SCALAR_FEATURES:
        missing = [column for column in required if column not in columns]
        if missing:
            dropped.append({"feature": name, "missing_columns": missing})
    return dropped


def is_failed_auth(event: LogEvent) -> bool:
    return (
        event.component == "sshd(pam_unix)"
        and event.event_id in AUTH_FAILURE_EVENT_IDS
        and "authentication failure" in event.content
    )


def is_privileged_attempt(event: LogEvent) -> bool:
    return event.username in PRIVILEGED_USERNAMES and is_failed_auth(event)


def is_ftp_connection(event: LogEvent) -> bool:
    return event.event_id == FTP_CONNECTION_EVENT_ID


def is_service_error(event: LogEvent) -> bool:
    return (
        event.event_id == SERVICE_ERROR_EVENT_ID
        and event.component == "logrotate"
        and "ALERT exited abnormally" in event.content
    )


def source_host(event: LogEvent) -> str | None:
    if event.source_ip:
        return event.source_ip
    match = _RHOST.search(event.content)
    if match is None:
        return None
    token = match.group(1).strip()
    return token or None


def window_start(moment: datetime) -> datetime:
    epoch = int(moment.timestamp())
    start = epoch // WINDOW_SECONDS * WINDOW_SECONDS
    return datetime.fromtimestamp(start, UTC)


def template_sort_key(event_id: str) -> tuple[int, int | str]:
    match = _TEMPLATE_ID.fullmatch(event_id)
    if match is None:
        return (1, event_id)
    return (0, int(match.group(1)))


def load_template_ids(session: Session) -> list[str]:
    ids = list(session.scalars(select(EventTemplate.event_id)).all())
    return sorted(ids, key=template_sort_key)


def load_events(session: Session, source_id: UUID | None) -> list[LogEvent]:
    stmt = select(LogEvent).where(LogEvent.event_timestamp.is_not(None))
    if source_id is not None:
        stmt = stmt.where(LogEvent.source_id == source_id)
    stmt = stmt.order_by(LogEvent.event_timestamp, LogEvent.line_number, LogEvent.id)
    return list(session.scalars(stmt).all())


def build_windows(events: list[LogEvent]) -> list[RawWindow]:
    grouped: dict[tuple[UUID, datetime], RawWindow] = {}
    for event in events:
        assert event.event_timestamp is not None
        start = window_start(event.event_timestamp)
        key = (event.source_id, start)
        window = grouped.get(key)
        if window is None:
            window = RawWindow(
                source_id=event.source_id,
                window_start=start,
                window_end=start + timedelta(seconds=WINDOW_SECONDS),
            )
            grouped[key] = window
        window.event_count += 1
        if is_failed_auth(event):
            window.failed_auth_count += 1
        if is_privileged_attempt(event):
            window.privileged_attempt_count += 1
        if is_ftp_connection(event):
            window.ftp_connection_count += 1
        if is_service_error(event):
            window.service_error_count += 1
        host = source_host(event)
        if host is not None:
            window.source_hosts.add(host)
        if event.username:
            window.usernames.add(event.username)
        if event.event_id:
            counts = window.template_counts
            counts[event.event_id] = counts.get(event.event_id, 0) + 1
        else:
            window.unmatched_templates += 1
        components = window.component_counts
        components[event.component] = components.get(event.component, 0) + 1
    return sorted(grouped.values(), key=lambda item: (item.window_start, str(item.source_id)))


def schema_for(
    train_windows: list[RawWindow],
    template_ids: list[str],
    dropped: list[dict[str, object]],
) -> FeatureSchema:
    dropped_names = {str(item["feature"]) for item in dropped}
    names: list[str] = []
    for name, _required in SCALAR_FEATURES:
        if name not in dropped_names:
            names.append(name)
    if "event_id" not in _missing_columns(dropped, "distinct_templates"):
        for event_id in template_ids:
            names.append(f"template_count:{event_id}")
        names.append("template_count:__other__")
    if "component" not in _missing_columns(dropped, "distinct_components"):
        components = sorted({name for window in train_windows for name in window.component_counts})
        for component in components:
            names.append(f"component_count:{component}")
        names.append("component_count:__other__")
    else:
        components = []
    return FeatureSchema(
        feature_names=tuple(names),
        template_ids=tuple(template_ids),
        component_names=tuple(components),
        dropped_features=tuple(dropped),
    )


def _missing_columns(dropped: list[dict[str, object]], feature: str) -> set[str]:
    for item in dropped:
        if item.get("feature") != feature:
            continue
        missing = item.get("missing_columns")
        if isinstance(missing, list):
            return {str(column) for column in missing}
    return set()


def _entropy(counts: list[int]) -> float:
    total = sum(counts)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count <= 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def vectorize(window: RawWindow, schema: FeatureSchema) -> dict[str, float]:
    values: dict[str, float] = dict.fromkeys(schema.feature_names, 0.0)
    present = set(schema.feature_names)
    if "event_count" in present:
        values["event_count"] = float(window.event_count)
    if "failed_auth_count" in present:
        values["failed_auth_count"] = float(window.failed_auth_count)
    if "distinct_source_hosts" in present:
        values["distinct_source_hosts"] = float(len(window.source_hosts))
    if "distinct_usernames" in present:
        values["distinct_usernames"] = float(len(window.usernames))
    if "privileged_attempt_count" in present:
        values["privileged_attempt_count"] = float(window.privileged_attempt_count)
    if "ftp_connection_count" in present:
        values["ftp_connection_count"] = float(window.ftp_connection_count)
    if "service_error_count" in present:
        values["service_error_count"] = float(window.service_error_count)
    if "distinct_templates" in present:
        values["distinct_templates"] = float(len(window.template_counts))
    if "distinct_components" in present:
        values["distinct_components"] = float(len(window.component_counts))

    template_parts: list[int] = []
    if any(name.startswith("template_count:") for name in schema.feature_names):
        known = set(schema.template_ids)
        other = window.unmatched_templates
        max_known = 0
        for event_id in schema.template_ids:
            count = window.template_counts.get(event_id, 0)
            values[f"template_count:{event_id}"] = float(count)
            template_parts.append(count)
            if count > max_known:
                max_known = count
        for event_id, count in window.template_counts.items():
            if event_id not in known:
                other += count
        values["template_count:__other__"] = float(other)
        template_parts.append(other)
        if "template_entropy" in present:
            values["template_entropy"] = _entropy(template_parts)
        if "max_template_count" in present:
            values["max_template_count"] = float(max_known)

    if any(name.startswith("component_count:") for name in schema.feature_names):
        known_components = set(schema.component_names)
        other = 0
        parts: list[int] = []
        for component in schema.component_names:
            count = window.component_counts.get(component, 0)
            values[f"component_count:{component}"] = float(count)
            parts.append(count)
        for component, count in window.component_counts.items():
            if component not in known_components:
                other += count
        values["component_count:__other__"] = float(other)
        parts.append(other)
        if "component_entropy" in present:
            values["component_entropy"] = _entropy(parts)
    return values


def matrix_rows(windows: list[RawWindow], schema: FeatureSchema) -> list[dict[str, float]]:
    return [vectorize(window, schema) for window in windows]
