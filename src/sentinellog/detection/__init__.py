"""Rule-based detection over stored log events.

Findings are analyst-priority alerts on unlabeled logs. They are not confirmed
compromise. ML, incidents, reports, and live collection stay unimplemented.
"""

from sentinellog.detection.routes import alerts_router, detection_router, rules_router

__all__ = ["alerts_router", "detection_router", "rules_router"]
