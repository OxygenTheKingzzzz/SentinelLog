"""Optional read-only live collection. File tails only; journald is reported, not followed."""

from sentinellog.live.routes import router

__all__ = ["router"]
