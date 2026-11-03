"""Rule-based detection over stored log events.

Findings are analyst-priority alerts on unlabeled logs. They are not confirmed
compromise. Anomaly scores live in sentinellog.ml and are not written here.
Confirmed incidents stay unimplemented. Investigation reports live in sentinellog.investigations.
"""

from sentinellog.detection.routes import alerts_router, detection_router, rules_router

__all__ = ["alerts_router", "detection_router", "rules_router"]
