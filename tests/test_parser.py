import csv
from datetime import UTC, datetime

import pytest
from tests.conftest import DATA

from sentinellog.ingestion.matcher import TemplateMatcher
from sentinellog.ingestion.parsing import (
    LineError,
    ParsedLine,
    parse_syslog_line,
    split_log_lines,
)
from sentinellog.normalization.timestamps import build_timestamp, parse_hms

RAW = DATA / "Linux_2k.log"
STRUCTURED = DATA / "Linux_2k.log_structured.csv"
TEMPLATES = DATA / "Linux_2k.log_templates.csv"


def _load():
    raw_bytes = RAW.read_bytes()
    lines = split_log_lines(raw_bytes.decode("utf-8"))
    with STRUCTURED.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    with TEMPLATES.open(newline="") as handle:
        templates = list(csv.DictReader(handle))
    return raw_bytes, lines, rows, templates


def test_real_file_shape():
    raw_bytes, lines, rows, templates = _load()
    assert not raw_bytes.endswith(b"\n")
    assert raw_bytes.count(b"\n") == 1999
    assert raw_bytes.count(b"\r") == 1999
    assert len(lines) == 2000
    assert len(rows) == 2000
    assert len(templates) == 118
    assert [row["LineId"] for row in rows] == [str(number) for number in range(1, 2001)]
    assert "\r" not in lines[0]
    assert lines[0].endswith(" ")
    assert b"\x00" not in raw_bytes


def test_parser_agrees_with_structured_csv_on_every_line():
    _raw_bytes, lines, rows, templates = _load()
    matcher = TemplateMatcher([(row["EventId"], row["EventTemplate"]) for row in templates])
    parsed: list[ParsedLine] = []
    errors: list[LineError] = []
    for number, line in enumerate(lines, start=1):
        result = parse_syslog_line(number, line)
        if isinstance(result, LineError):
            errors.append(result)
            continue
        matched = matcher.match(result.content)
        if matched is not None:
            result.event_id, result.event_template = matched
        parsed.append(result)

    assert len(parsed) + len(errors) == len(lines) == 2000
    assert errors == []
    assert len({row["Level"] for row in rows}) == 1
    assert rows[0]["Level"] == "combo"

    ips = 0
    usernames = 0
    missing_pid = 0
    for result, row in zip(parsed, rows, strict=True):
        assert result.line_number == int(row["LineId"])
        assert result.month == row["Month"]
        assert result.day == int(row["Date"])
        assert result.time_text == row["Time"]
        assert result.hostname == row["Level"]
        assert result.component == row["Component"]
        expected_pid = int(row["PID"]) if row["PID"] else None
        assert result.pid == expected_pid
        assert result.content == row["Content"]
        assert result.event_id == row["EventId"]
        assert result.event_template == row["EventTemplate"]
        assert result.raw_line == lines[result.line_number - 1]
        ips += result.source_ip is not None
        usernames += result.username is not None
        missing_pid += result.pid is None

    assert missing_pid == 151
    assert ips == 1245
    assert usernames == 621
    assert parsed[0].source_ip == "218.188.2.4"
    assert parsed[0].username is None
    assert parsed[0].content == rows[0]["Content"]
    assert parsed[0].raw_line.endswith(" ")
    assert parsed[3].username == "root"
    assert parsed[898].component == "-- root"
    assert parsed[898].pid == 2421
    assert "combo  -- root" in parsed[898].raw_line
    assert parsed[145].component == "syslogd 1.4.1"
    assert parsed[145].pid is None
    assert sum(item.month == "Jun" for item in parsed) == 604
    assert sum(item.month == "Jul" for item in parsed) == 1396


def test_year_is_opt_in_and_utc():
    _raw_bytes, lines, _rows, _templates = _load()
    first = parse_syslog_line(1, lines[0])
    assert isinstance(first, ParsedLine)
    clock = parse_hms(first.time_text)
    assert clock is not None
    assert build_timestamp(None, first.month, first.day, clock) is None
    stamped = build_timestamp(2005, first.month, first.day, clock)
    assert stamped == datetime(2005, 6, 14, 15, 16, 1, tzinfo=UTC)


def test_malformed_lines_are_explicit_errors():
    bad = parse_syslog_line(1, "this is not syslog")
    assert isinstance(bad, LineError)
    empty = parse_syslog_line(2, "   ")
    assert isinstance(empty, LineError)
    huge = parse_syslog_line(3, "x" * 20000)
    assert isinstance(huge, LineError)
    assert huge.message == "line exceeds maximum length"


def test_template_specificity_prefers_user_root():
    content = (
        "authentication failure; logname= uid=0 euid=0 tty=NODEVssh "
        "ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root"
    )
    matcher = TemplateMatcher(
        [
            (
                "E16",
                "authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=<*>",
            ),
            (
                "E18",
                "authentication failure; logname= uid=0 euid=0 tty=NODEVssh "
                "ruser= rhost=<*>  user=root",
            ),
        ]
    )
    assert matcher.match(content) == (
        "E18",
        "authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=<*>  user=root",
    )


def test_level_column_is_not_a_severity_field():
    from sentinellog.models import LogEvent

    names = set(LogEvent.__table__.columns.keys())
    assert "hostname" in names
    assert "level" not in names
    assert "severity" not in names


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", []),
        ("\n", [""]),
        ("a\n", ["a"]),
        ("a\n\n", ["a", ""]),
        ("a\r\nb\r\n", ["a", "b"]),
        ("a", ["a"]),
    ],
)
def test_split_log_lines(text: str, expected: list[str]):
    assert split_log_lines(text) == expected
