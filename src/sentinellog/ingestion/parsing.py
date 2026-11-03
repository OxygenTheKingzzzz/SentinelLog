"""Parse classic syslog lines.

Grammar, verified against Linux_2k:

    Mmm dd hh:mm:ss hostname tag: message

The day may be space-padded. `tag` is `component[pid]` or a component that can
contain spaces (`syslogd 1.4.1`, `-- root`). The separator between tag and
message is the first ": ". PID brackets are recognized only at the end of the
tag. Message text is stored with surrounding whitespace removed so it agrees
with the Loghub structured CSV; `raw_line` keeps the original line body,
including trailing spaces. CR/LF terminators are not part of the line body.
"""

import hashlib
import re
from dataclasses import dataclass

from sentinellog.normalization.entities import extract_ip, extract_username
from sentinellog.normalization.timestamps import MONTH_ABBRS, parse_hms

MAX_LINE_CHARS = 16_384
_MONTH_ALT = "|".join(MONTH_ABBRS)
_HEAD = re.compile(rf"^({_MONTH_ALT})\s+(\d{{1,2}})\s+(\d{{2}}:\d{{2}}:\d{{2}})\s+(\S+)\s+(.*)$")
_PID_TAG = re.compile(r"^(.*)\[(\d+)\]$")


@dataclass
class ParsedLine:
    line_number: int
    raw_line: str
    raw_line_sha256: str
    month: str
    day: int
    time_text: str
    hostname: str
    component: str
    pid: int | None
    content: str
    source_ip: str | None
    username: str | None
    event_id: str | None = None
    event_template: str | None = None


@dataclass(frozen=True)
class LineError:
    line_number: int
    raw_line: str
    message: str


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def decode_text(data: bytes) -> str:
    if b"\x00" in data:
        raise ValueError("file contains NUL bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("file is not valid UTF-8") from exc


def split_log_lines(text: str) -> list[str]:
    """Split on LF. A trailing newline does not create an extra line. Strip one trailing CR."""
    if text == "":
        return []
    parts = text.split("\n")
    if parts[-1] == "":
        parts.pop()
    return [part[:-1] if part.endswith("\r") else part for part in parts]


def parse_syslog_line(line_number: int, raw_line: str) -> ParsedLine | LineError:
    if len(raw_line) > MAX_LINE_CHARS:
        return LineError(line_number, raw_line[:4000], "line exceeds maximum length")
    if raw_line.strip() == "":
        return LineError(line_number, raw_line, "empty line")
    match = _HEAD.match(raw_line)
    if match is None:
        return LineError(line_number, raw_line, "line does not match syslog grammar")
    month, day_text, time_text, hostname, rest = match.groups()
    day = int(day_text)
    if not 1 <= day <= 31:
        return LineError(line_number, raw_line, "day is out of range")
    if parse_hms(time_text) is None:
        return LineError(line_number, raw_line, "time is out of range")
    separator = rest.find(": ")
    if separator <= 0:
        return LineError(line_number, raw_line, "missing component or message separator")
    tag = rest[:separator].strip()
    message = rest[separator + 2 :]
    if tag == "":
        return LineError(line_number, raw_line, "missing component")
    pid_match = _PID_TAG.match(tag)
    pid: int | None
    if pid_match:
        component = pid_match.group(1).strip()
        pid = int(pid_match.group(2))
        if component == "":
            return LineError(line_number, raw_line, "missing component")
        if pid > 2_147_483_647:
            return LineError(line_number, raw_line, "pid is out of range")
    else:
        component = tag
        pid = None
    content = message.strip()
    if content == "":
        return LineError(line_number, raw_line, "empty message")
    return ParsedLine(
        line_number=line_number,
        raw_line=raw_line,
        raw_line_sha256=sha256_text(raw_line),
        month=month,
        day=day,
        time_text=time_text,
        hostname=hostname,
        component=component,
        pid=pid,
        content=content,
        source_ip=extract_ip(content),
        username=extract_username(content),
    )
