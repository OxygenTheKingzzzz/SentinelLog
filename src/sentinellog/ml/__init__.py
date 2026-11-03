"""Experimental anomaly detection over stored log events.

Scores live in anomaly_scores. They are not written to security_alerts.
There is no ground truth on Linux_2k, so this package does not report
precision, recall, F1, or ROC-AUC.
"""

from sentinellog.ml.routes import router

__all__ = ["router"]
