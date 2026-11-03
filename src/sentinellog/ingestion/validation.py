"""Upload checks.

Log text is untrusted. Filenames are metadata only and are never opened, joined
onto a filesystem path, passed to a shell, or evaluated. Bytes are not executed.
"""

from pathlib import Path

RAW_SUFFIXES = frozenset({".log", ".txt"})
CSV_SUFFIXES = frozenset({".csv"})
MAX_FILENAME = 255


class FileRejected(ValueError):
    """The upload is unsafe or the wrong shape. No ingestion job is created."""


def validate_filename(name: str | None, allowed_suffixes: frozenset[str]) -> str:
    if name is None or name.strip() == "":
        raise FileRejected("filename is required")
    if name != Path(name).name or "/" in name or "\\" in name or ".." in name:
        raise FileRejected("filename is not allowed")
    if any(ord(char) < 32 for char in name):
        raise FileRejected("filename is not allowed")
    if len(name) > MAX_FILENAME:
        raise FileRejected("filename is too long")
    suffix = Path(name).suffix.lower()
    if suffix not in allowed_suffixes:
        raise FileRejected(f"extension {suffix or '(none)'} is not allowed")
    return name


def ensure_text_bytes(data: bytes, *, max_bytes: int) -> None:
    if len(data) > max_bytes:
        raise FileRejected(f"file exceeds limit of {max_bytes} bytes")
    if b"\x00" in data:
        raise FileRejected("file contains NUL bytes")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FileRejected("file is not valid UTF-8") from exc
