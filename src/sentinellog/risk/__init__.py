"""Risk classification. Predictions are not ground truth.

Accuracy is stored only after a held-out test against verified labels.
"""

from sentinellog.risk.routes import router

__all__ = ["router"]
