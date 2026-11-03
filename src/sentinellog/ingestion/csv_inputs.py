"""CSV readers for template catalogs and the structured reference export."""

import csv
import io
import re

from sentinellog.ingestion.validation import FileRejected
from sentinellog.normalization.timestamps import MONTH_ABBRS, parse_hms

TEMPLATE_COLUMNS = ("EventId", "EventTemplate")
STRUCTURED_COLUMNS = (
    "LineId",
    "Month",
    "Date",
    "Time",
    "Level",
    "Component",
    "PID",
    "Content",
    "EventId",
    "EventTemplate",
)
_EVENT_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
_MONTHS = set(MONTH_ABBRS)


def _reader(data: bytes) -> csv.DictReader:
    text = data.decode("utf-8")
    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise FileRejected("csv has no header")
    return reader


def _require_columns(reader: csv.DictReader, required: tuple[str, ...]) -> None:
    fields = [(name or "").strip().lstrip("\ufeff") for name in reader.fieldnames or []]
    missing = [column for column in required if column not in fields]
    if missing:
        raise FileRejected("csv missing columns: " + ", ".join(missing))


def read_template_rows(data: bytes) -> list[tuple[int, str, str]]:
    reader = _reader(data)
    _require_columns(reader, TEMPLATE_COLUMNS)
    rows: list[tuple[int, str, str]] = []
    for index, row in enumerate(reader, start=2):
        event_id = (row.get("EventId") or "").strip()
        template = row.get("EventTemplate")
        if template is None:
            template = ""
        rows.append((index, event_id, template))
    return rows


def canonical_structured_line(fields: dict[str, str]) -> str:
    """Stable identity for a structured row. This is not the original syslog line."""
    ordered = [fields[column] for column in STRUCTURED_COLUMNS]
    return "|".join(ordered)


def read_structured_rows(data: bytes) -> list[tuple[int, dict[str, str] | str]]:
    """Return (csv_line, row) or (csv_line, error_message). Level is the hostname column."""
    reader = _reader(data)
    _require_columns(reader, STRUCTURED_COLUMNS)
    parsed: list[tuple[int, dict[str, str] | str]] = []
    for index, raw in enumerate(reader, start=2):
        row = {
            column: (raw.get(column) if raw.get(column) is not None else "")
            for column in STRUCTURED_COLUMNS
        }
        line_id = row["LineId"].strip()
        if not line_id.isdigit() or int(line_id) < 1:
            parsed.append((index, "LineId must be a positive integer"))
            continue
        if row["Month"].strip() not in _MONTHS:
            parsed.append((index, "Month is not a syslog abbreviation"))
            continue
        date = row["Date"].strip()
        if not date.isdigit() or not 1 <= int(date) <= 31:
            parsed.append((index, "Date is out of range"))
            continue
        if parse_hms(row["Time"].strip()) is None:
            parsed.append((index, "Time is out of range"))
            continue
        if row["Level"].strip() == "":
            parsed.append((index, "Level (hostname) is empty"))
            continue
        if row["Component"].strip() == "":
            parsed.append((index, "Component is empty"))
            continue
        pid = row["PID"].strip()
        if pid and (not pid.isdigit() or int(pid) > 2_147_483_647):
            parsed.append((index, "PID is not an integer"))
            continue
        if row["Content"].strip() == "":
            parsed.append((index, "Content is empty"))
            continue
        event_id = row["EventId"].strip()
        if not _EVENT_ID.match(event_id):
            parsed.append((index, "EventId is not valid"))
            continue
        if row["EventTemplate"].strip() == "":
            parsed.append((index, "EventTemplate is empty"))
            continue
        normalized = {
            "LineId": str(int(line_id)),
            "Month": row["Month"].strip(),
            "Date": str(int(date)),
            "Time": row["Time"].strip(),
            "Level": row["Level"].strip(),
            "Component": row["Component"].strip(),
            "PID": pid,
            "Content": row["Content"].strip(),
            "EventId": event_id,
            "EventTemplate": row["EventTemplate"],
        }
        parsed.append((index, normalized))
    return parsed
