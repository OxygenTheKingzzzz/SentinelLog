"""Isolation Forest plus a robust-z baseline on one frozen feature matrix."""

import math
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from sentinellog.ml.constants import (
    BASELINE_Z_THRESHOLD,
    CONTAMINATION,
    ISOLATION_SCORE_THRESHOLD,
    MAX_BASELINE_FEATURES,
    N_ESTIMATORS,
    NO_GROUND_TRUTH,
    RANDOM_STATE,
    TOP_CONTRIBUTIONS,
    Z_CAP,
    Z_CONSISTENCY,
)


def json_number(value: float) -> int | float:
    if math.isfinite(value) and float(value).is_integer() and abs(value) < 2**53:
        return int(value)
    return float(value)


def feature_matrix(rows: list[dict[str, float]], names: list[str]) -> np.ndarray:
    return np.asarray([[row[name] for name in names] for row in rows], dtype=np.float64)


def column_stats(
    matrix: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[str]]:
    medians = np.median(matrix, axis=0)
    abs_dev = np.abs(matrix - medians)
    mads = np.median(abs_dev, axis=0)
    mean_abs = np.mean(abs_dev, axis=0)
    scales = np.where(mads > 0, mads, mean_abs)
    kinds: list[str] = []
    for mad, mean_a in zip(mads, mean_abs, strict=True):
        if mad > 0:
            kinds.append("mad")
        elif mean_a > 0:
            kinds.append("mean_abs_dev")
        else:
            kinds.append("constant")
    return medians, mads, scales, kinds


def robust_z(value: float, median: float, scale: float) -> float:
    delta = value - median
    if scale > 0:
        return Z_CONSISTENCY * delta / scale
    if delta == 0:
        return 0.0
    return math.copysign(Z_CAP, delta)


def fit_forest(matrix: np.ndarray) -> IsolationForest:
    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        bootstrap=False,
        n_jobs=1,
    )
    model.fit(matrix)
    return model


def _baseline_rows(
    values: dict[str, float],
    names: list[str],
    medians: dict[str, float],
    mads: dict[str, float],
    scales: dict[str, float],
    kinds: dict[str, str],
) -> tuple[float, list[dict[str, object]], int]:
    ranked: list[tuple[float, str, float]] = []
    for name in names:
        score = robust_z(values[name], medians[name], scales[name])
        ranked.append((abs(score), name, score))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    above = [item for item in ranked if item[0] >= BASELINE_Z_THRESHOLD]
    chosen = above[:MAX_BASELINE_FEATURES] if above else ranked[:1]
    details = [
        {
            "feature": name,
            "value": json_number(values[name]),
            "train_median": json_number(medians[name]),
            "train_mad": json_number(mads[name]),
            "train_scale": json_number(scales[name]),
            "scale_kind": kinds[name],
            "robust_z": json_number(score),
        }
        for _abs_score, name, score in chosen
    ]
    baseline_score = ranked[0][0] if ranked else 0.0
    return baseline_score, details, len(above)


def score_rows(
    forest: IsolationForest,
    rows: list[dict[str, float]],
    names: list[str],
    medians: dict[str, float],
    mads: dict[str, float],
    scales: dict[str, float],
    kinds: dict[str, str],
) -> list[dict[str, Any]]:
    matrix = feature_matrix(rows, names)
    decision = forest.decision_function(matrix)
    isolation_scores = -decision
    median_vector = np.asarray([medians[name] for name in names], dtype=np.float64)
    contributions = np.zeros_like(matrix)
    for index, _name in enumerate(names):
        altered = matrix.copy()
        altered[:, index] = median_vector[index]
        contributions[:, index] = isolation_scores - (-forest.decision_function(altered))

    scored: list[dict[str, Any]] = []
    for row_index, values in enumerate(rows):
        isolation_score = float(isolation_scores[row_index])
        baseline_score, baseline_details, n_above = _baseline_rows(
            values, names, medians, mads, scales, kinds
        )
        order = sorted(
            range(len(names)),
            key=lambda index: (-float(contributions[row_index, index]), names[index]),
        )
        isolation_details = [
            {
                "feature": names[index],
                "value": json_number(values[names[index]]),
                "train_median": json_number(medians[names[index]]),
                "score_delta": json_number(float(contributions[row_index, index])),
            }
            for index in order[:TOP_CONTRIBUTIONS]
        ]
        scored.append(
            {
                "isolation_score": isolation_score,
                "baseline_score": float(baseline_score),
                "flagged_isolation": isolation_score > ISOLATION_SCORE_THRESHOLD,
                "flagged_baseline": baseline_score >= BASELINE_Z_THRESHOLD,
                "explanation": {
                    "no_ground_truth": True,
                    "metrics": None,
                    "metrics_note": NO_GROUND_TRUTH,
                    "summary": (
                        f"isolation_score {isolation_score:.6f} "
                        f"(flag when > {ISOLATION_SCORE_THRESHOLD:g}); "
                        f"baseline max |robust z| {baseline_score:.6f} "
                        f"(flag when >= {BASELINE_Z_THRESHOLD:g}). "
                        "No ground-truth label."
                    ),
                    "isolation_contributions": isolation_details,
                    "baseline": baseline_details,
                    "baseline_features_at_or_above_threshold": n_above,
                },
            }
        )
    return scored


def validation_summary(scored: list[dict[str, Any]]) -> dict[str, object]:
    isolation = [float(row["isolation_score"]) for row in scored]
    baseline = [float(row["baseline_score"]) for row in scored]
    return {
        "n_windows": len(scored),
        "isolation_score_min": json_number(min(isolation)),
        "isolation_score_max": json_number(max(isolation)),
        "isolation_score_median": json_number(float(np.median(np.asarray(isolation)))),
        "baseline_score_min": json_number(min(baseline)),
        "baseline_score_max": json_number(max(baseline)),
        "baseline_score_median": json_number(float(np.median(np.asarray(baseline)))),
        "flagged_isolation": sum(1 for row in scored if row["flagged_isolation"]),
        "flagged_baseline": sum(1 for row in scored if row["flagged_baseline"]),
        "flagged_either": sum(
            1 for row in scored if row["flagged_isolation"] or row["flagged_baseline"]
        ),
        "ground_truth": False,
        "metrics": None,
        "metrics_note": NO_GROUND_TRUTH,
    }


def stats_as_dicts(
    names: list[str],
    medians: np.ndarray,
    mads: np.ndarray,
    scales: np.ndarray,
    kinds: list[str],
) -> tuple[dict[str, float], dict[str, float], dict[str, float], dict[str, str]]:
    median_map = {name: float(medians[index]) for index, name in enumerate(names)}
    mad_map = {name: float(mads[index]) for index, name in enumerate(names)}
    scale_map = {name: float(scales[index]) for index, name in enumerate(names)}
    kind_map = {name: kinds[index] for index, name in enumerate(names)}
    return median_map, mad_map, scale_map, kind_map
