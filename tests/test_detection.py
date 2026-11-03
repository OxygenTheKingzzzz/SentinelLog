"""Rule engine on the real Linux_2k file. Alerts are findings, not labels."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from tests.test_ingest import RAW, TEMPLATES

from sentinellog.cli import main
from sentinellog.detection.backfill import assign_source_year, backfill_timestamps
from sentinellog.detection.catalog import DISCLAIMER
from sentinellog.detection.service import detect, ensure_builtin_rules, update_rule
from sentinellog.ingestion.service import create_source, import_raw_log, import_template_csv
from sentinellog.models import AuditLog, DetectionRule, LogEvent, LogSource, SecurityAlert

# Documented counts for datasets/Linux_2k.log with source_year=2005.
EXPECTED = {
    "ssh-auth-failures-by-source": {
        "alerts": 41,
        "severity": "medium",
        "threshold": 5,
        "window_seconds": 86400,
        "window_type": "tumbling",
    },
    "ssh-bruteforce-burst": {
        "alerts": 30,
        "severity": "high",
        "threshold": 10,
        "window_seconds": 60,
        "window_type": "sliding",
    },
    "privileged-user-auth-failures": {
        "alerts": 26,
        "severity": "high",
        "threshold": 5,
        "window_seconds": 86400,
        "window_type": "tumbling",
    },
    "unknown-username-attempts": {
        "alerts": 18,
        "severity": "low",
        "threshold": 1,
        "window_seconds": 3600,
        "window_type": "tumbling",
    },
    "ftp-connection-burst": {
        "alerts": 31,
        "severity": "medium",
        "threshold": 20,
        "window_seconds": 60,
        "window_type": "sliding",
    },
    "anonymous-ftp-auth": {
        "alerts": 1,
        "severity": "medium",
        "threshold": 1,
        "window_seconds": 60,
        "window_type": "sliding",
    },
    "repeated-service-failure": {
        "alerts": 6,
        "severity": "low",
        "threshold": 7,
        "window_seconds": 604800,
        "window_type": "tumbling",
    },
    "unusual-session-sequence": {
        "alerts": 6,
        "severity": "medium",
        "threshold": 6,
        "window_seconds": 60,
        "window_type": "sliding",
    },
    "event-frequency-spike": {
        "alerts": 3,
        "severity": "medium",
        "threshold": 30,
        "window_seconds": 60,
        "window_type": "tumbling",
    },
}


def _import_without_year(db, name: str):
    source = create_source(db, name=name, description="historical sample", source_year=None)
    import_template_csv(
        db,
        source_id=source.id,
        filename="Linux_2k.log_templates.csv",
        data=TEMPLATES,
        actor="test",
    )
    job = import_raw_log(db, source_id=source.id, filename="Linux_2k.log", data=RAW, actor="test")
    assert job.lines_parsed == 2000
    return source


def _counts(db) -> dict[str, int]:
    rows = db.execute(
        select(DetectionRule.name, func.count(SecurityAlert.id))
        .join(SecurityAlert, SecurityAlert.rule_id == DetectionRule.id)
        .group_by(DetectionRule.name)
    ).all()
    return {name: count for name, count in rows}


def test_backfill_fills_nulls_and_preserves_existing(db):
    source = create_source(db, name="partial", description=None, source_year=None)
    payload = (
        b"Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; "
        b"logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 \n"
        b"Jun 15 04:06:20 combo logrotate: ALERT exited abnormally with [1]\n"
    )
    import_raw_log(db, source_id=source.id, filename="partial.log", data=payload, actor="test")
    untouched = backfill_timestamps(db, source_id=source.id, actor="test")
    assert untouched.updated == 0
    assert untouched.skipped_no_year == 2
    events = db.scalars(
        select(LogEvent).where(LogEvent.source_id == source.id).order_by(LogEvent.line_number)
    ).all()
    assert all(event.event_timestamp is None for event in events)
    sentinel = datetime(1999, 1, 1, tzinfo=UTC)
    events[0].event_timestamp = sentinel
    db.commit()
    assign_source_year(db, source, 2005, actor="test")
    db.commit()
    filled = backfill_timestamps(db, source_id=source.id, actor="test")
    assert filled.updated == 1
    assert filled.already_set == 1
    db.expire_all()
    again = db.scalars(
        select(LogEvent).where(LogEvent.source_id == source.id).order_by(LogEvent.line_number)
    ).all()
    assert again[0].event_timestamp == sentinel
    assert again[1].event_timestamp == datetime(2005, 6, 15, 4, 6, 20, tzinfo=UTC)
    second = backfill_timestamps(db, source_id=source.id, actor="test")
    assert second.updated == 0
    assert second.already_set == 2
    db.expire_all()
    kept = db.scalar(
        select(LogEvent).where(LogEvent.source_id == source.id, LogEvent.line_number == 1)
    )
    assert kept is not None
    assert kept.event_timestamp == sentinel

    refused = main(["backfill", "--source-name", "plain-missing"])
    assert refused == 2
    bare = create_source(db, name="plain", description=None, source_year=None)
    import_raw_log(db, source_id=bare.id, filename="partial.log", data=payload, actor="test")
    missing_year = main(["backfill", "--source-name", "plain"])
    assert missing_year == 2
    db.expire_all()
    bare = db.scalar(select(LogSource).where(LogSource.name == "plain"))
    assert bare is not None
    assert bare.source_year is None
    still_null = db.scalar(select(LogEvent).where(LogEvent.source_id == bare.id))
    assert still_null is not None
    assert still_null.event_timestamp is None
    assigned = main(["backfill", "--source-name", "plain", "--year", "2005"])
    assert assigned == 0
    db.expire_all()
    bare = db.scalar(select(LogSource).where(LogSource.name == "plain"))
    assert bare is not None
    assert bare.source_year == 2005
    stamped = db.scalars(select(LogEvent).where(LogEvent.source_id == bare.id)).all()
    assert stamped
    assert all(
        event.event_timestamp is not None and event.event_timestamp.year == 2005
        for event in stamped
    )


def test_engine_on_linux_2k_and_second_run(db):
    source = _import_without_year(db, "linux-2k")
    nulls = db.scalar(
        select(func.count())
        .select_from(LogEvent)
        .where(LogEvent.source_id == source.id, LogEvent.event_timestamp.is_(None))
    )
    assert nulls == 2000
    before = detect(db, source_id=source.id, actor="test")
    assert before.created == 0
    assert sum(before.by_rule.values()) == 0

    assign_source_year(db, source, 2005, actor="test")
    db.commit()
    filled = backfill_timestamps(db, source_id=source.id, actor="test")
    assert filled.updated == 2000
    first = db.scalar(
        select(LogEvent).where(LogEvent.source_id == source.id, LogEvent.line_number == 1)
    )
    assert first is not None
    assert first.event_timestamp == datetime(2005, 6, 14, 15, 16, 1, tzinfo=UTC)

    run = detect(db, source_id=source.id, actor="test")
    assert run.created == sum(spec["alerts"] for spec in EXPECTED.values())
    assert run.updated == 0
    assert run.skipped == 0
    assert run.by_rule == {name: spec["alerts"] for name, spec in EXPECTED.items()}
    stored = _counts(db)
    assert stored == {name: spec["alerts"] for name, spec in EXPECTED.items()}

    rules = {row.name: row for row in db.scalars(select(DetectionRule)).all()}
    events = {
        row.id: row
        for row in db.scalars(select(LogEvent).where(LogEvent.source_id == source.id)).all()
    }
    alerts = db.scalars(select(SecurityAlert).where(SecurityAlert.source_id == source.id)).all()
    assert len(alerts) == run.created
    assert len({alert.dedup_key for alert in alerts}) == len(alerts)
    unknown_lines: set[int] = set()
    service_lines: set[int] = set()
    for alert in alerts:
        rule = rules[alert.details["rule_name"]]
        spec = EXPECTED[rule.name]
        assert alert.rule_id == rule.id
        assert alert.rule_version == 1
        assert rule.version == 1
        assert alert.severity == spec["severity"]
        assert alert.threshold == spec["threshold"]
        assert alert.window_seconds == spec["window_seconds"]
        assert alert.window_type == spec["window_type"]
        assert alert.status == "open"
        assert alert.source_id == source.id
        assert DISCLAIMER in alert.explanation
        assert alert.threshold >= 1
        assert len(alert.event_ids) == len(alert.line_numbers)
        assert len(alert.event_ids) >= alert.threshold
        assert len(set(alert.event_ids)) == len(alert.event_ids)
        evidence = []
        for event_id, line_number in zip(alert.event_ids, alert.line_numbers, strict=True):
            event = events[UUID(event_id)]
            assert event.line_number == line_number
            assert event.event_timestamp is not None
            evidence.append(event)
        assert alert.first_event_at == min(event.event_timestamp for event in evidence)
        assert alert.last_event_at == max(event.event_timestamp for event in evidence)
        span = timedelta(seconds=alert.window_seconds)
        assert alert.window_end - alert.window_start == span
        if alert.window_type == "tumbling":
            for event in evidence:
                assert alert.window_start <= event.event_timestamp < alert.window_end
        else:
            for event in evidence:
                assert alert.window_start <= event.event_timestamp <= alert.window_end
                assert event.event_timestamp - alert.window_start <= span
        _assert_attributes(rule.name, alert, evidence)
        if rule.name == "unknown-username-attempts":
            unknown_lines.update(event.line_number for event in evidence)
        if rule.name == "repeated-service-failure":
            service_lines.update(event.line_number for event in evidence)

    unknown_events = [event for event in events.values() if event.event_id in {"E27", "E112"}]
    assert unknown_lines == {event.line_number for event in unknown_events}
    assert len(unknown_lines) == 118
    service_events = [event for event in events.values() if event.event_id == "E8"]
    assert len(service_events) == 43
    assert len(service_lines) == 42
    left_out = [event for event in service_events if event.line_number not in service_lines]
    assert len(left_out) == 1
    assert left_out[0].month == "Jun"
    assert left_out[0].day == 15

    second = detect(db, source_id=source.id, actor="test")
    assert second.created == 0
    assert second.updated == 0
    assert second.skipped == len(alerts)
    assert db.scalar(select(func.count()).select_from(SecurityAlert)) == len(alerts)


def _assert_attributes(name: str, alert: SecurityAlert, evidence: list[LogEvent]) -> None:
    for event in evidence:
        if name in {"ssh-auth-failures-by-source", "ssh-bruteforce-burst"}:
            assert event.component == "sshd(pam_unix)"
            assert event.event_id in {"E16", "E17", "E18", "E19"}
            assert "authentication failure" in event.content
            assert f"rhost={alert.group_value}" in event.content
            assert alert.source_address == alert.group_value
        elif name == "privileged-user-auth-failures":
            assert event.username == "root"
            assert "user=root" in event.content
            assert event.event_id == "E18"
            assert f"rhost={alert.group_value}" in event.content
            assert alert.source_address == alert.group_value
        elif name == "unknown-username-attempts":
            assert event.event_id in {"E27", "E112"}
            assert event.component == alert.group_value
            assert alert.source_address is None
        elif name == "ftp-connection-burst":
            assert event.event_id == "E29"
            assert event.component == "ftpd"
            assert event.source_ip == alert.group_value
            assert alert.source_address == event.source_ip
        elif name == "anonymous-ftp-auth":
            assert event.event_id == "E9"
            assert event.username == "anonymous"
            assert event.source_ip == alert.group_value
            assert alert.source_address == event.source_ip
        elif name == "repeated-service-failure":
            assert event.event_id == "E8"
            assert event.component == "logrotate"
            assert "ALERT exited abnormally" in event.content
            assert alert.group_value == "logrotate"
        elif name == "unusual-session-sequence":
            assert event.event_id in {"E101", "E102", "E103"}
            assert event.username == alert.group_value
            assert alert.group_value == "test"
        elif name == "event-frequency-spike":
            assert event.component == alert.group_value
        else:
            raise AssertionError(name)


def test_disabled_rule_produces_no_alerts(db):
    source = _import_without_year(db, "linux-disabled")
    assign_source_year(db, source, 2005, actor="test")
    db.commit()
    backfill_timestamps(db, source_id=source.id, actor="test")
    rules = ensure_builtin_rules(db, actor="test")
    db.commit()
    ftp = next(rule for rule in rules if rule.name == "ftp-connection-burst")
    assert ftp.version == 1
    update_rule(db, ftp.id, actor="test", enabled=False, fields_set={"enabled"})
    db.expire_all()
    ftp = db.get(DetectionRule, ftp.id)
    assert ftp is not None
    assert ftp.enabled is False
    assert ftp.version == 1
    result = detect(db, source_id=source.id, actor="test")
    assert "ftp-connection-burst" in result.disabled
    assert "ftp-connection-burst" not in result.by_rule
    stored = _counts(db)
    assert "ftp-connection-burst" not in stored
    for name, spec in EXPECTED.items():
        if name == "ftp-connection-burst":
            continue
        assert stored[name] == spec["alerts"]


def test_rule_update_bumps_version_and_writes_audit(client, db):
    listed = client.get("/api/v1/rules")
    assert listed.status_code == 200
    body = listed.json()
    assert len(body) == 9
    rule = next(item for item in body if item["name"] == "ssh-bruteforce-burst")
    assert rule["version"] == 1
    assert rule["enabled"] is True
    assert rule["logic"]["threshold"] == 10
    assert rule["logic"]["window_type"] == "sliding"
    patched = client.patch(
        f"/api/v1/rules/{rule['id']}",
        json={"threshold": 12, "window_seconds": 120},
    )
    assert patched.status_code == 200, patched.text
    updated = patched.json()
    assert updated["version"] == 2
    assert updated["logic"]["threshold"] == 12
    assert updated["logic"]["window_seconds"] == 120
    assert updated["logic"]["window_type"] == "sliding"
    assert updated["enabled"] is True
    db.expire_all()
    audit = db.scalar(
        select(AuditLog)
        .where(AuditLog.action == "detection_rule.update", AuditLog.entity_id == rule["id"])
        .order_by(AuditLog.created_at.desc())
    )
    assert audit is not None
    assert audit.details["before"]["version"] == 1
    assert audit.details["after"]["version"] == 2
    assert audit.details["before"]["threshold"] == 10
    assert audit.details["after"]["threshold"] == 12
    assert audit.details["after"]["window_seconds"] == 120
    disabled = client.patch(f"/api/v1/rules/{rule['id']}", json={"enabled": False})
    assert disabled.status_code == 200
    assert disabled.json()["version"] == 2
    assert disabled.json()["enabled"] is False
    db.expire_all()
    audits = db.scalars(
        select(AuditLog).where(
            AuditLog.action == "detection_rule.update",
            AuditLog.entity_id == rule["id"],
        )
    ).all()
    assert len(audits) == 2
    assert audits[-1].details["after"]["enabled"] is False
    assert audits[-1].details["after"]["version"] == 2


def test_status_transition_note_and_audit(client, db):
    source = client.post(
        "/api/v1/sources",
        json={"name": "anon", "source_year": 2005},
    )
    assert source.status_code == 201
    source_id = source.json()["id"]
    templates = client.post(
        f"/api/v1/sources/{source_id}/ingest/templates",
        files={"file": ("Linux_2k.log_templates.csv", TEMPLATES, "text/csv")},
    )
    assert templates.status_code == 200
    line = (
        b"Jul 24 02:38:23 combo ftpd[26991]: ANONYMOUS FTP LOGIN FROM 84.102.20.2,  (anonymous)\n"
    )
    raw = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("anon.log", line, "text/plain")},
    )
    assert raw.status_code == 200
    assert raw.json()["lines_parsed"] == 1
    run = client.post("/api/v1/detection/run", params={"source_id": source_id})
    assert run.status_code == 200, run.text
    assert run.json()["by_rule"]["anonymous-ftp-auth"] == 1
    assert run.json()["by_rule"]["ftp-connection-burst"] == 0
    listed = client.get("/api/v1/alerts", params={"rule": "anonymous-ftp-auth", "limit": 10})
    assert listed.status_code == 200
    page = listed.json()
    assert page["total"] == 1
    alert = page["items"][0]
    assert alert["status"] == "open"
    assert alert["severity"] == "medium"
    assert alert["source_address"] == "84.102.20.2"
    assert alert["line_numbers"] == [1]
    assert DISCLAIMER in alert["explanation"]
    changed = client.post(
        f"/api/v1/alerts/{alert['id']}/status",
        json={"status": "investigating", "note": "checking the anonymous login"},
    )
    assert changed.status_code == 200, changed.text
    body = changed.json()
    assert body["status"] == "investigating"
    assert len(body["notes"]) == 1
    assert body["notes"][0]["note"] == "checking the anonymous login"
    assert body["notes"][0]["from_status"] == "open"
    assert body["notes"][0]["to_status"] == "investigating"
    same = client.post(
        f"/api/v1/alerts/{alert['id']}/status",
        json={"status": "investigating", "note": "again"},
    )
    assert same.status_code == 400
    db.expire_all()
    audit = db.scalar(
        select(AuditLog).where(
            AuditLog.action == "security_alert.status",
            AuditLog.entity_id == alert["id"],
        )
    )
    assert audit is not None
    assert audit.details["from_status"] == "open"
    assert audit.details["to_status"] == "investigating"
    assert audit.details["note"] == "checking the anonymous login"
    filtered = client.get(
        "/api/v1/alerts", params={"status": "investigating", "severity": "medium"}
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    closed = client.get("/api/v1/alerts", params={"status": "resolved"})
    assert closed.json()["total"] == 0
