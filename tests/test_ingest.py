import csv
from datetime import UTC, datetime

from sqlalchemy import func, select
from tests.conftest import DATA

from sentinellog.cli import main
from sentinellog.ingestion.service import (
    create_source,
    import_raw_log,
    import_structured_csv,
    import_template_csv,
)
from sentinellog.models import (
    AuditLog,
    DetectionRule,
    IngestionError,
    LogEvent,
    LogSource,
    SecurityAlert,
)
from sentinellog.normalization.storage import dedup_key, quality_report, search_events

RAW = (DATA / "Linux_2k.log").read_bytes()
STRUCTURED = (DATA / "Linux_2k.log_structured.csv").read_bytes()
TEMPLATES = (DATA / "Linux_2k.log_templates.csv").read_bytes()


def _rows():
    with (DATA / "Linux_2k.log_structured.csv").open(newline="") as handle:
        return list(csv.DictReader(handle))


def test_import_real_dataset_accounts_for_every_line(db):
    source = create_source(
        db,
        name="linux-2k",
        description="historical sample",
        source_year=None,
    )
    templates = import_template_csv(
        db,
        source_id=source.id,
        filename="Linux_2k.log_templates.csv",
        data=TEMPLATES,
        actor="test",
    )
    assert templates.status == "completed"
    assert templates.lines_total == 118
    assert templates.lines_parsed == 118
    assert templates.lines_errored == 0
    assert templates.stats["inserted"] == 118

    job = import_raw_log(
        db,
        source_id=source.id,
        filename="Linux_2k.log",
        data=RAW,
        actor="test",
    )
    assert job.status == "completed"
    assert job.lines_total == 2000
    assert job.lines_parsed == 2000
    assert job.lines_errored == 0
    assert job.duplicates_skipped == 0
    assert job.conflicts == 0
    assert job.lines_parsed + job.lines_errored == job.lines_total
    assert job.stats["missing_pid"] == 151
    assert job.stats["with_ip"] == 1245
    assert job.stats["with_username"] == 621
    assert job.stats["with_timestamp"] == 0
    assert job.stats["unmatched_templates"] == 0

    events = db.scalars(
        select(LogEvent).where(LogEvent.source_id == source.id).order_by(LogEvent.line_number)
    ).all()
    assert len(events) == 2000
    rows = _rows()
    for event, row in zip(events, rows, strict=True):
        assert event.line_number == int(row["LineId"])
        assert event.hostname == row["Level"] == "combo"
        assert event.component == row["Component"]
        assert event.pid == (int(row["PID"]) if row["PID"] else None)
        assert event.content == row["Content"]
        assert event.event_id == row["EventId"]
        assert event.event_template == row["EventTemplate"]
        assert event.month == row["Month"]
        assert event.day == int(row["Date"])
        assert event.time_of_day.strftime("%H:%M:%S") == row["Time"]
        assert event.event_timestamp is None
        assert event.origin == "raw_log"
        assert event.dedup_key == dedup_key(source.id, event.line_number, event.raw_line_sha256)
        assert "\n" not in event.raw_line and "\r" not in event.raw_line

    assert events[0].raw_line.endswith(" ")
    assert source.hostname == "combo"

    again = import_raw_log(
        db,
        source_id=source.id,
        filename="Linux_2k.log",
        data=RAW,
        actor="test",
    )
    assert again.lines_total == 2000
    assert again.lines_parsed == 0
    assert again.lines_errored == 0
    assert again.duplicates_skipped == 2000
    assert again.conflicts == 0
    assert (
        again.lines_parsed + again.lines_errored + again.duplicates_skipped + again.conflicts
        == 2000
    )
    assert db.scalar(select(func.count()).select_from(LogEvent)) == 2000
    assert events[0].job_id == job.id

    validated = import_structured_csv(
        db,
        source_id=source.id,
        filename="Linux_2k.log_structured.csv",
        data=STRUCTURED,
        actor="test",
        mode="validate",
    )
    assert validated.lines_total == 2000
    assert validated.lines_parsed == 2000
    assert validated.lines_errored == 0

    ftpd, ftpd_total = search_events(db, source_id=source.id, component="ftpd", limit=1)
    assert ftpd_total == 916
    assert len(ftpd) == 1
    _page, e29_total = search_events(db, source_id=source.id, event_id="E29", limit=1)
    assert e29_total == 909
    _page, text_total = search_events(db, source_id=source.id, q="user unknown", limit=5)
    assert text_total == sum(1 for row in rows if "user unknown" in row["Content"].lower())
    _page, escaped = search_events(db, source_id=source.id, q="%not-in-log%", limit=1)
    assert escaped == 0
    _page, june_total = search_events(db, source_id=source.id, month="Jun", limit=1)
    assert june_total == 604
    _page, host_total = search_events(db, source_id=source.id, hostname="combo", limit=1)
    assert host_total == 2000
    # No year was configured, so a timestamp filter matches nothing.
    _page, ranged = search_events(
        db,
        source_id=source.id,
        occurred_from=datetime(2005, 6, 14, 15, 16, 1, tzinfo=UTC),
        occurred_to=datetime(2005, 6, 14, 15, 16, 1, tzinfo=UTC),
    )
    assert ranged == 0

    report = quality_report(db, source.id)
    assert report is not None
    assert report["events"] == 2000
    assert report["parse_errors"] == 0
    assert report["events_missing_pid"] == 151
    assert report["events_missing_timestamp"] == 2000
    assert report["events_unmatched_template"] == 0
    assert report["events_missing_ip"] == 2000 - 1245
    assert report["events_missing_username"] == 2000 - 621

    assert db.scalar(select(func.count()).select_from(SecurityAlert)) == 0
    assert db.scalar(select(func.count()).select_from(DetectionRule)) == 0
    assert db.scalar(select(func.count()).select_from(AuditLog)) >= 3


def test_configured_year_is_utc_and_filters(db):
    source = create_source(db, name="linux-2005", description=None, source_year=2005)
    import_template_csv(
        db,
        source_id=source.id,
        filename="Linux_2k.log_templates.csv",
        data=TEMPLATES,
        actor="test",
    )
    job = import_raw_log(db, source_id=source.id, filename="Linux_2k.log", data=RAW, actor="test")
    assert job.stats["with_timestamp"] == 2000
    first = db.scalar(
        select(LogEvent).where(LogEvent.source_id == source.id, LogEvent.line_number == 1)
    )
    assert first is not None
    assert first.event_timestamp == datetime(2005, 6, 14, 15, 16, 1, tzinfo=UTC)
    _page, total = search_events(
        db,
        source_id=source.id,
        occurred_from=datetime(2005, 6, 14, 15, 16, 1, tzinfo=UTC),
        occurred_to=datetime(2005, 6, 14, 15, 16, 1, tzinfo=UTC),
    )
    assert total == 1


def test_bad_line_is_counted_and_conflict_keeps_original(db):
    source = create_source(db, name="small", description=None, source_year=None)
    payload = RAW + b"\nthis is not a syslog line\n"
    job = import_raw_log(db, source_id=source.id, filename="mixed.log", data=payload, actor="test")
    assert job.lines_total == 2001
    assert job.lines_parsed == 2000
    assert job.lines_errored == 1
    assert job.lines_parsed + job.lines_errored == job.lines_total
    error = db.scalar(select(IngestionError).where(IngestionError.job_id == job.id))
    assert error is not None
    assert error.error_kind == "parse"
    assert error.line_number == 2001

    changed = payload.replace(b"combo", b"other", 1)
    conflict = import_raw_log(
        db, source_id=source.id, filename="mixed.log", data=changed, actor="test"
    )
    assert conflict.conflicts == 1
    assert conflict.duplicates_skipped == 1999
    assert conflict.lines_errored == 1
    assert (
        conflict.lines_parsed
        + conflict.lines_errored
        + conflict.duplicates_skipped
        + conflict.conflicts
        == conflict.lines_total
    )
    kept = db.scalar(
        select(LogEvent).where(LogEvent.source_id == source.id, LogEvent.line_number == 1)
    )
    assert kept is not None
    assert "combo" in kept.raw_line
    stored = db.scalar(
        select(func.count()).select_from(LogEvent).where(LogEvent.source_id == source.id)
    )
    assert stored == 2000


def test_structured_import_dedups(db):
    source = create_source(db, name="from-csv", description=None, source_year=None)
    job = import_structured_csv(
        db,
        source_id=source.id,
        filename="Linux_2k.log_structured.csv",
        data=STRUCTURED,
        actor="test",
        mode="import",
    )
    assert job.lines_parsed == 2000
    assert job.lines_errored == 0
    event = db.scalar(select(LogEvent).where(LogEvent.line_number == 1))
    assert event is not None
    assert event.origin == "structured_csv"
    assert event.hostname == "combo"
    assert event.component == "sshd(pam_unix)"
    assert event.pid == 19939
    again = import_structured_csv(
        db,
        source_id=source.id,
        filename="Linux_2k.log_structured.csv",
        data=STRUCTURED,
        actor="test",
        mode="import",
    )
    assert again.duplicates_skipped == 2000
    assert db.scalar(select(func.count()).select_from(LogEvent)) == 2000


def test_schema_matches_models(db):
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from sentinellog.models import Base

    context = MigrationContext.configure(db.connection())
    diff = compare_metadata(context, Base.metadata)
    assert diff == []


def test_cli_bundled_import(db):
    code = main(["import-bundled", "--dataset-dir", str(DATA), "--source-name", "cli-linux"])
    assert code == 0
    code_again = main(["import-bundled", "--dataset-dir", str(DATA), "--source-name", "cli-linux"])
    assert code_again == 0
    total = db.scalar(select(func.count()).select_from(LogEvent))
    assert total == 2000
    db.expire_all()
    source = db.scalar(select(LogSource).where(LogSource.name == "cli-linux"))
    assert source is not None
    assert source.source_year == 2005
    header = db.scalar(
        select(LogEvent).where(LogEvent.source_id == source.id, LogEvent.line_number == 1)
    )
    assert header is not None
    assert header.event_timestamp == datetime(2005, 6, 14, 15, 16, 1, tzinfo=UTC)
    # The FTP banner clock is one second earlier and the text contains 2005.
    # The stored timestamp follows the syslog header plus the configured year.
    banner = db.scalar(
        select(LogEvent).where(LogEvent.source_id == source.id, LogEvent.line_number == 263)
    )
    assert banner is not None
    assert "2005" in banner.content
    assert "13:16:30" in banner.content
    assert banner.event_timestamp == datetime(2005, 6, 22, 13, 16, 31, tzinfo=UTC)
    audit = db.scalar(
        select(LogEvent).where(LogEvent.source_id == source.id, LogEvent.line_number == 1986)
    )
    assert audit is not None
    assert "1122475266" in audit.content
    assert audit.event_timestamp == datetime(2005, 7, 27, 14, 41, 59, tzinfo=UTC)
