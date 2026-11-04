"""Small in-process window for expensive HTTP routes. Not a distributed limiter."""

import re
import threading
import time

_IMPORT = re.compile(r"^/api/v1/sources/[^/]+/ingest/(raw|templates|structured)$")
_DETECT = re.compile(r"^/api/v1/detection/run$")
_ML = re.compile(r"^/api/v1/ml/(train|score)$")
_RISK = re.compile(r"^/api/v1/risk/(train|bands|weak-labels|labels/import)$")
_PDF = re.compile(r"^/api/v1/investigations/[^/]+/report\.pdf$")


def bucket_for(method: str, path: str) -> str | None:
    if method == "POST" and _IMPORT.match(path):
        return "import"
    if method == "POST" and _DETECT.match(path):
        return "detect"
    if method == "POST" and _ML.match(path):
        return "ml"
    if method == "POST" and _RISK.match(path):
        return "risk"
    if method == "GET" and _PDF.match(path):
        return "pdf"
    return None


class WindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, host: str, bucket: str, limit: int, window_seconds: float) -> bool:
        now = time.monotonic()
        key = (host, bucket)
        with self._lock:
            if len(self._hits) >= 10000:
                self._hits = {k: v for k, v in self._hits.items()
                              if v and now - v[-1] < window_seconds}
                if key not in self._hits and len(self._hits) >= 10000:
                    return False
            recent = [stamp for stamp in self._hits.get(key, []) if now - stamp < window_seconds]
            if len(recent) >= limit:
                self._hits[key] = recent
                return False
            recent.append(now)
            self._hits[key] = recent
            return True
