"""Deterministic text normalization. This is not a learned vocabulary."""

import hashlib
import math
import re
from datetime import datetime

_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b")
_BLK = re.compile(r"\bblk_-?\d+\b")
_NUM = re.compile(r"\b\d+\b")
_SPACE = re.compile(r"\s+")

# Whole words only. The BGL/Thunderbird alert token is removed before this runs.
_SEVERITY_WORDS = (
    ("fatal", 3),
    ("severe", 3),
    ("critical", 3),
    ("panic", 3),
    ("error", 2),
    ("fail", 2),
    ("denied", 2),
    ("invalid", 2),
    ("warn", 1),
    ("info", 0),
    ("debug", 0),
)


def normalize_template(text: str) -> str:
    """Collapse variables so near-duplicate messages share a group key."""
    value = text.lower()
    value = _UUID.sub("<*>", value)
    value = _IP.sub("<*>", value)
    value = _BLK.sub("blk_<*>", value)
    value = _HEX.sub("<*>", value)
    value = _NUM.sub("<*>", value)
    value = _SPACE.sub(" ", value).strip()
    return value


def group_key(text: str) -> str:
    normalized = normalize_template(text)
    if len(normalized) > 512:
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return normalized or "empty"


def keyword_severity(text: str) -> int:
    words = set(re.findall(r"[a-z]+", text.lower()))
    rank = 0
    for word, value in _SEVERITY_WORDS:
        if word in words:
            rank = max(rank, value)
    return rank


def level_rank(level: str | None) -> int:
    if not level:
        return 0
    token = level.lower()
    if token in {"fatal", "severe", "critical", "panic", "failure"}:
        return 3
    if token in {"error", "err", "kill"}:
        return 2
    if token in {"warn", "warning"}:
        return 1
    return 0


def hour_cycle(moment: datetime | None) -> tuple[float, float]:
    if moment is None:
        return 0.0, 0.0
    seconds = moment.hour * 3600 + moment.minute * 60 + moment.second
    angle = 2 * math.pi * seconds / 86400
    return math.sin(angle), math.cos(angle)
