"""One classification example. `label` is ground truth only when the caller says so."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Example:
    key: str
    content: str
    group_key: str
    timestamp: datetime | None
    component: str
    pid: int | None
    severity_rank: int
    label: str | None
