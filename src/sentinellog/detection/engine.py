"""Evaluate enabled rules against stored log events.

Dedup key = rule name + source id + group entity + window start (UTC, to the
second), joined with an ASCII unit separator. Re-running the engine skips an
identical finding and updates the same row when the evidence or the rule
version changed. It does not delete alerts, and it does not reset lifecycle
status or analyst notes.

Null timestamps are ignored. Severity copied onto an alert is the rule's
analyst priority.
"""

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinellog.clock import utcnow
from sentinellog.detection.catalog import DISCLAIMER
from sentinellog.models import LogEvent, SecurityAlert

_RHOST = re.compile(r"rhost=(\S+)")
_GROUP_LIMIT = 256


@dataclass(frozen=True)
class Finding:
    source_id: UUID
    group_value: str
    event_ids: list[str]
    line_numbers: list[int]
    first_event_at: datetime
    last_event_at: datetime
    window_start: datetime
    window_end: datetime
    source_address: str | None
    count: int


@dataclass(frozen=True)
class DetectionRunResult:
    created: int
    updated: int
    skipped: int
    by_rule: dict[str, int]
    disabled: list[str]

    def as_dict(self) -> dict[str, object]:
        return {
            "created": self.created,
            "updated": self.updated,
            "skipped": self.skipped,
            "by_rule": dict(sorted(self.by_rule.items())),
            "disabled": list(self.disabled),
        }


def dedup_key(rule_name: str, source_id: UUID, group_value: str, window_start: datetime) -> str:
    start = _fmt(window_start)
    return "\x1f".join((rule_name, str(source_id), group_value, start))


def _fmt(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _logic_list(logic: dict, key: str) -> list[str] | None:
    value = logic.get(key)
    if value is None:
        return None
    return [str(item) for item in value]


def _matches(event: LogEvent, logic: dict) -> bool:
    event_ids = _logic_list(logic, "event_ids")
    if event_ids is not None and event.event_id not in event_ids:
        return False
    components = _logic_list(logic, "components")
    if components is not None and event.component not in components:
        return False
    needle = logic.get("content_contains")
    if needle and str(needle) not in event.content:
        return False
    usernames = _logic_list(logic, "usernames")
    if usernames is not None and event.username not in usernames:
        return False
    return True


def _group_value(event: LogEvent, group_by: str) -> str | None:
    if group_by == "rhost":
        match = _RHOST.search(event.content)
        if match is None:
            return None
        value = match.group(1).strip()
        return value or None
    if group_by == "source_ip":
        return event.source_ip
    if group_by == "username":
        return event.username
    if group_by == "component":
        return event.component or None
    raise ValueError(f"unsupported group_by {group_by}")


def _window_seconds(logic: dict) -> int:
    window = int(logic["window_seconds"])
    if window < 1:
        raise ValueError("window_seconds must be positive")
    return window


def _threshold(logic: dict) -> int:
    threshold = int(logic["threshold"])
    if threshold < 1:
        raise ValueError("threshold must be positive")
    return threshold


def _tumbling_start(moment: datetime, window_seconds: int) -> datetime:
    epoch = int(moment.timestamp())
    start = epoch // window_seconds * window_seconds
    return datetime.fromtimestamp(start, UTC)


def _ordered(events: list[LogEvent]) -> list[LogEvent]:
    return sorted(
        events, key=lambda event: (event.event_timestamp, event.line_number, str(event.id))
    )


def _finding(
    events: list[LogEvent],
    *,
    group_value: str,
    window_start: datetime,
    window_end: datetime,
    source_address: str | None,
) -> Finding:
    ordered = _ordered(events)
    first = min(event.event_timestamp for event in ordered)
    last = max(event.event_timestamp for event in ordered)
    if first is None or last is None:
        raise ValueError("evidence is missing a timestamp")
    return Finding(
        source_id=ordered[0].source_id,
        group_value=group_value,
        event_ids=[str(event.id) for event in ordered],
        line_numbers=[event.line_number for event in ordered],
        first_event_at=first,
        last_event_at=last,
        window_start=window_start,
        window_end=window_end,
        source_address=source_address,
        count=len(ordered),
    )


def findings_for_events(logic: dict, events: list[LogEvent]) -> list[Finding]:
    """Return findings for one rule against one source's timestamped events."""
    window_type = str(logic["window_type"])
    if window_type not in {"sliding", "tumbling"}:
        raise ValueError(f"unsupported window_type {window_type}")
    window = _window_seconds(logic)
    threshold = _threshold(logic)
    group_by = str(logic["group_by"])
    address_from_group = bool(logic.get("source_address_from_group"))
    grouped: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_timestamp is None or not _matches(event, logic):
            continue
        group = _group_value(event, group_by)
        if group is None:
            continue
        if len(group) > _GROUP_LIMIT:
            raise ValueError("group value exceeds 256 characters")
        grouped[group].append(event)

    findings: list[Finding] = []
    for group, members in grouped.items():
        source_address = group if address_from_group else None
        if window_type == "tumbling":
            buckets: dict[datetime, list[LogEvent]] = defaultdict(list)
            for event in members:
                assert event.event_timestamp is not None
                buckets[_tumbling_start(event.event_timestamp, window)].append(event)
            for start, bucket in buckets.items():
                if len(bucket) < threshold:
                    continue
                findings.append(
                    _finding(
                        bucket,
                        group_value=group,
                        window_start=start,
                        window_end=start + timedelta(seconds=window),
                        source_address=source_address,
                    )
                )
            continue
        ordered = _ordered(members)
        index = 0
        total = len(ordered)
        while index < total:
            opened = ordered[index].event_timestamp
            assert opened is not None
            cursor = index
            hit: int | None = None
            while cursor < total:
                moment = ordered[cursor].event_timestamp
                assert moment is not None
                if (moment - opened).total_seconds() > window:
                    break
                if cursor - index + 1 >= threshold:
                    hit = cursor
                    break
                cursor += 1
            if hit is None:
                index += 1
                continue
            end = hit
            while end + 1 < total:
                moment = ordered[end + 1].event_timestamp
                assert moment is not None
                if (moment - opened).total_seconds() > window:
                    break
                end += 1
            findings.append(
                _finding(
                    ordered[index : end + 1],
                    group_value=group,
                    window_start=opened,
                    window_end=opened + timedelta(seconds=window),
                    source_address=source_address,
                )
            )
            index = end + 1
    return findings


def _render(template: str, fields: dict[str, object]) -> str:
    return str(template).format(**fields).strip()


def _same(
    alert: SecurityAlert,
    finding: Finding,
    *,
    version: int,
    severity: str,
    threshold: int,
    window_seconds: int,
    window_type: str,
    explanation: str,
    title: str,
) -> bool:
    return (
        alert.rule_version == version
        and alert.severity == severity
        and alert.threshold == threshold
        and alert.window_seconds == window_seconds
        and alert.window_type == window_type
        and list(alert.event_ids) == finding.event_ids
        and list(alert.line_numbers) == finding.line_numbers
        and alert.explanation == explanation
        and alert.title == title
        and alert.group_value == finding.group_value
        and alert.source_address == finding.source_address
        and alert.window_start == finding.window_start
        and alert.window_end == finding.window_end
        and alert.first_event_at == finding.first_event_at
        and alert.last_event_at == finding.last_event_at
    )


def _apply(
    alert: SecurityAlert,
    finding: Finding,
    *,
    version: int,
    severity: str,
    threshold: int,
    window_seconds: int,
    window_type: str,
    explanation: str,
    title: str,
    details: dict,
) -> None:
    alert.rule_version = version
    alert.severity = severity
    alert.threshold = threshold
    alert.window_seconds = window_seconds
    alert.window_type = window_type
    alert.explanation = explanation
    alert.title = title
    alert.group_value = finding.group_value
    alert.source_address = finding.source_address
    alert.window_start = finding.window_start
    alert.window_end = finding.window_end
    alert.first_event_at = finding.first_event_at
    alert.last_event_at = finding.last_event_at
    alert.event_ids = finding.event_ids
    alert.line_numbers = finding.line_numbers
    alert.details = details
    alert.updated_at = utcnow()


def run_detection(
    session: Session,
    *,
    source_id: UUID | None,
    rules: list,
) -> DetectionRunResult:
    """Evaluate ``rules`` and insert or refresh alerts. Caller commits."""
    enabled = [rule for rule in rules if rule.enabled]
    disabled = [rule.name for rule in rules if not rule.enabled]
    event_stmt = select(LogEvent).where(LogEvent.event_timestamp.is_not(None))
    alert_stmt = select(SecurityAlert)
    if source_id is not None:
        event_stmt = event_stmt.where(LogEvent.source_id == source_id)
        alert_stmt = alert_stmt.where(SecurityAlert.source_id == source_id)
    by_source: dict[UUID, list[LogEvent]] = defaultdict(list)
    for event in session.scalars(event_stmt).all():
        by_source[event.source_id].append(event)
    existing = {row.dedup_key: row for row in session.scalars(alert_stmt).all()}

    created = 0
    updated = 0
    skipped = 0
    by_rule: dict[str, int] = {}
    for rule in enabled:
        if not rule.severity:
            raise ValueError(f"rule {rule.name} has no severity")
        logic = dict(rule.logic)
        threshold = _threshold(logic)
        window_seconds = _window_seconds(logic)
        window_type = str(logic["window_type"])
        findings_seen = 0
        for events in by_source.values():
            for finding in findings_for_events(logic, events):
                findings_seen += 1
                users = _logic_list(logic, "usernames")
                fields = {
                    "count": finding.count,
                    "group": finding.group_value,
                    "first": _fmt(finding.first_event_at),
                    "last": _fmt(finding.last_event_at),
                    "threshold": threshold,
                    "window_seconds": window_seconds,
                    "window_type": window_type,
                    "severity": rule.severity,
                    "users": ", ".join(users) if users else "n/a",
                    "rule": rule.name,
                }
                explanation = _render(str(logic["explanation_template"]), fields)
                if "not a confirmed compromise" not in explanation:
                    explanation = f"{explanation} {DISCLAIMER}"
                title = _render(str(logic["title_template"]), fields)[:300]
                details = {
                    "rule_name": rule.name,
                    "group_by": logic.get("group_by"),
                    "required_attributes": logic.get("required_attributes") or [],
                    "window_end_exclusive": window_type == "tumbling",
                    "disclaimer": DISCLAIMER,
                }
                key = dedup_key(
                    rule.name, finding.source_id, finding.group_value, finding.window_start
                )
                current = existing.get(key)
                if current is None:
                    alert = SecurityAlert(
                        rule_id=rule.id,
                        source_id=finding.source_id,
                        rule_version=rule.version,
                        title=title,
                        severity=rule.severity,
                        status="open",
                        source_address=finding.source_address,
                        explanation=explanation,
                        threshold=threshold,
                        window_seconds=window_seconds,
                        window_type=window_type,
                        window_start=finding.window_start,
                        window_end=finding.window_end,
                        first_event_at=finding.first_event_at,
                        last_event_at=finding.last_event_at,
                        event_ids=finding.event_ids,
                        line_numbers=finding.line_numbers,
                        group_value=finding.group_value,
                        dedup_key=key,
                        details=details,
                    )
                    session.add(alert)
                    existing[key] = alert
                    created += 1
                    continue
                if _same(
                    current,
                    finding,
                    version=rule.version,
                    severity=rule.severity or "",
                    threshold=threshold,
                    window_seconds=window_seconds,
                    window_type=window_type,
                    explanation=explanation,
                    title=title,
                ):
                    skipped += 1
                    continue
                _apply(
                    current,
                    finding,
                    version=rule.version,
                    severity=rule.severity or "",
                    threshold=threshold,
                    window_seconds=window_seconds,
                    window_type=window_type,
                    explanation=explanation,
                    title=title,
                    details=details,
                )
                updated += 1
        by_rule[rule.name] = findings_seen
    return DetectionRunResult(
        created=created,
        updated=updated,
        skipped=skipped,
        by_rule=by_rule,
        disabled=disabled,
    )
