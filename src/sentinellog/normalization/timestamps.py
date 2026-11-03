"""Timestamp pieces for syslog lines that do not carry a year or a timezone.

Assumption, applied only when a year is explicitly configured on the log source
(or via SOURCE_YEAR as the default for a new source): these lines have no
timezone. The configured civil year/month/day/time is stored as UTC. The year
is never read out of the message text, including FTP banners that contain a
calendar date or kernel audit() epochs.
"""

from datetime import UTC, datetime, time

MONTH_ABBRS: tuple[str, ...] = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)
MONTH_NUMBERS: dict[str, int] = {name: index for index, name in enumerate(MONTH_ABBRS, start=1)}


def parse_hms(value: str) -> time | None:
    parts = value.split(":")
    if len(parts) != 3:
        return None
    try:
        hour, minute, second = (int(part) for part in parts)
    except ValueError:
        return None
    if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
        return None
    return time(hour, minute, second)


def build_timestamp(year: int | None, month: str, day: int, clock: time) -> datetime | None:
    """Return a UTC timestamp, or None when no year is configured or the date is impossible."""
    if year is None:
        return None
    month_number = MONTH_NUMBERS.get(month)
    if month_number is None:
        return None
    try:
        return datetime(
            year,
            month_number,
            day,
            clock.hour,
            clock.minute,
            clock.second,
            tzinfo=UTC,
        )
    except ValueError:
        return None
