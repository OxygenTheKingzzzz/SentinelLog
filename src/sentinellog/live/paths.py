"""Authorize a local file path. Log text is never part of the decision."""

import os
from pathlib import Path

from sentinellog.config import get_settings


class PathRejected(Exception):
    pass


def allow_roots() -> list[Path]:
    roots: list[Path] = []
    for part in get_settings().live_allow_roots.split(os.pathsep):
        text = part.strip()
        if not text:
            continue
        path = Path(text)
        if not path.is_absolute():
            continue
        roots.append(path)
    return roots


def resolve_allowed_path(raw: str, roots: list[Path] | None = None) -> Path:
    """Return the resolved file path or raise PathRejected.

    Traversal, relative paths, NUL bytes, and symlink escapes are rejected.
    The resolved path must sit inside an absolute allowlist root.
    """
    if "\x00" in raw:
        raise PathRejected("path contains NUL")
    if not raw.startswith("/"):
        raise PathRejected("path must be absolute")
    candidate = Path(raw)
    if any(part == ".." for part in candidate.parts):
        raise PathRejected("path traversal is not allowed")
    chosen = allow_roots() if roots is None else roots
    if not chosen:
        raise PathRejected("live allowlist is empty")
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise PathRejected("symlinks are not allowed")
    resolved = candidate.resolve(strict=False)
    if not resolved.is_absolute():
        raise PathRejected("path must be absolute")
    inside = False
    for root in chosen:
        root_resolved = root.resolve(strict=False)
        try:
            resolved.relative_to(root_resolved)
        except ValueError:
            continue
        if resolved == root_resolved:
            raise PathRejected("path must be a file inside the allowlist, not the root")
        inside = True
        break
    if not inside:
        raise PathRejected("path is outside the live allowlist")
    if resolved.is_symlink():
        raise PathRejected("path must not be a symlink")
    if not resolved.parent.is_dir():
        raise PathRejected("parent directory does not exist")
    if resolved.exists() and not resolved.is_file():
        raise PathRejected("path is not a regular file")
    return resolved
