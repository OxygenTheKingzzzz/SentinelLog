"""Held-out metrics. Training-fold scores are never returned as the test result."""

from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from sentinellog.risk.constants import NOT_EVALUATED


def _float(value: float) -> float:
    return float(value)


def classification_metrics(
    y_true: list[str],
    y_pred: list[str],
    *,
    labels: list[str],
    scores: np.ndarray | None = None,
    score_columns: list[str] | None = None,
) -> dict[str, Any]:
    """Score one untouched test set.

    `scores` is a 1-d positive-class score for binary tasks, or a probability
    matrix whose columns follow `score_columns` for a multiclass task.
    ROC-AUC and PR-AUC are omitted when the test labels make them undefined.
    """
    if not y_true or len(y_true) != len(y_pred):
        raise ValueError("predictions and labels must be the same non-empty length")
    present = set(y_true)
    if len(present) < 2:
        return {
            "status": "not_evaluated",
            "metrics": None,
            "metrics_note": NOT_EVALUATED,
            "detail": "The held-out test set contains one class, so accuracy is not reported.",
        }

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        average=None,
        zero_division=0,
    )
    macro_p, macro_r, macro_f, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        average="macro",
        zero_division=0,
    )
    weighted_p, weighted_r, weighted_f, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        average="weighted",
        zero_division=0,
    )
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    per_class = []
    for index, label in enumerate(labels):
        per_class.append(
            {
                "label": label,
                "precision": _float(precision[index]),
                "recall": _float(recall[index]),
                "f1": _float(f1[index]),
                "support": int(support[index]),
            }
        )
    payload: dict[str, Any] = {
        "accuracy": _float(accuracy_score(y_true, y_pred)),
        "precision_macro": _float(macro_p),
        "recall_macro": _float(macro_r),
        "f1_macro": _float(macro_f),
        "precision_weighted": _float(weighted_p),
        "recall_weighted": _float(weighted_r),
        "f1_weighted": _float(weighted_f),
        "per_class": per_class,
        "confusion_matrix": {"labels": labels, "matrix": matrix.astype(int).tolist()},
        "roc_auc": None,
        "pr_auc": None,
        "roc_auc_note": None,
        "pr_auc_note": None,
        "support": int(len(y_true)),
    }
    if len(labels) == 2:
        positive = labels[1]
        positive_row = next(row for row in per_class if row["label"] == positive)
        payload["precision"] = positive_row["precision"]
        payload["recall"] = positive_row["recall"]
        payload["f1"] = positive_row["f1"]
        payload["positive_label"] = positive
    else:
        payload["precision"] = payload["precision_macro"]
        payload["recall"] = payload["recall_macro"]
        payload["f1"] = payload["f1_macro"]
        payload["positive_label"] = None
        payload["precision_note"] = "Multiclass precision/recall/F1 are macro averages."

    if scores is None:
        payload["roc_auc_note"] = "No score was produced for this model."
        payload["pr_auc_note"] = payload["roc_auc_note"]
        return {"status": "evaluated", "metrics": payload, "metrics_note": None, "detail": None}

    if len(labels) == 2:
        if present != set(labels):
            missing = sorted(set(labels) - present)
            note = f"ROC-AUC is undefined because the test set has no {missing[0]} rows."
            payload["roc_auc_note"] = note
            payload["pr_auc_note"] = note
        else:
            binary = np.asarray([1 if label == labels[1] else 0 for label in y_true])
            payload["roc_auc"] = _float(roc_auc_score(binary, scores))
            payload["pr_auc"] = _float(average_precision_score(binary, scores))
        return {"status": "evaluated", "metrics": payload, "metrics_note": None, "detail": None}

    if score_columns is None or scores.ndim != 2 or scores.shape[1] != len(score_columns):
        payload["roc_auc_note"] = "Multiclass ROC-AUC needs a probability column per class."
        payload["pr_auc_note"] = "Multiclass PR-AUC is not reported as one number."
        return {"status": "evaluated", "metrics": payload, "metrics_note": None, "detail": None}

    column_index = {label: index for index, label in enumerate(score_columns)}
    if any(label not in column_index for label in labels) or present != set(labels):
        payload["roc_auc_note"] = (
            "Multiclass ROC-AUC is undefined unless every class appears in the test set."
        )
    else:
        ordered = np.column_stack([scores[:, column_index[label]] for label in labels])
        payload["roc_auc"] = _float(
            roc_auc_score(y_true, ordered, multi_class="ovr", average="macro", labels=labels)
        )
    payload["pr_auc_note"] = "Multiclass PR-AUC is not reported as one number."
    return {"status": "evaluated", "metrics": payload, "metrics_note": None, "detail": None}


def not_evaluated(detail: str) -> dict[str, Any]:
    return {
        "status": "not_evaluated",
        "metrics": None,
        "metrics_note": NOT_EVALUATED,
        "detail": detail,
    }
