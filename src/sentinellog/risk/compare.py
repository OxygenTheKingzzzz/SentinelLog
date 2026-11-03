"""Train Isolation Forest, Random Forest, and TF-IDF logistic regression.

The held-out test groups are not used to fit features, choose a model, or set a threshold.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

from sentinellog.risk.constants import (
    BAND_QUANTILES,
    BINARY_LABELS,
    BINARY_TO_RISK,
    CV_CAP,
    CV_FOLDS,
    FOREST_ESTIMATORS,
    ISOLATION_CONTAMINATION,
    ISOLATION_ESTIMATORS,
    RISK_LEVELS,
    TEST_CAP,
    TEST_FRACTION,
    TRAIN_CAP,
)
from sentinellog.risk.features import FeatureEncoder
from sentinellog.risk.metrics import classification_metrics, not_evaluated
from sentinellog.risk.records import Example
from sentinellog.risk.split import (
    holdout_positive_groups,
    positive_group_count,
    split_groups,
)

_SUPERVISED = ("random_forest", "tfidf_logreg")


@dataclass
class ScoredExample:
    example: Example
    predicted_label: str
    predicted_risk: str
    class_confidence: float | None
    anomaly_score: float | None
    score_kind: str
    explanation: dict[str, Any]
    split_role: str


@dataclass
class ModelRun:
    algorithm: str
    task: str
    fit_protocol: str
    n_train: int
    n_test: int
    metrics_status: str
    metrics_note: str | None
    detail: str | None
    metrics: dict[str, Any] | None
    cv: dict[str, Any]
    predictions: list[ScoredExample] = field(default_factory=list)
    bundle: dict[str, Any] | None = None


def cap_examples(examples: list[Example], cap: int, seed: int) -> list[Example]:
    """Drop whole groups first. A group larger than the remaining room is sampled."""
    if len(examples) <= cap:
        return list(examples)
    grouped: dict[str, list[Example]] = defaultdict(list)
    for item in examples:
        grouped[item.group_key].append(item)
    rng = np.random.RandomState(seed)
    keys = sorted(grouped)
    rng.shuffle(keys)
    kept: list[Example] = []
    for key in keys:
        bucket = grouped[key]
        if len(kept) >= cap:
            break
        room = cap - len(kept)
        if len(bucket) <= room:
            kept.extend(bucket)
        elif not kept:
            indexes = rng.choice(len(bucket), size=room, replace=False)
            kept.extend(bucket[int(index)] for index in sorted(indexes))
            break
    return kept


def _labels_for(task: str) -> list[str]:
    if task == "binary_anomaly":
        return list(BINARY_LABELS)
    if task == "multiclass_risk":
        return list(RISK_LEVELS)
    raise ValueError(f"unknown task {task}")


def _display_risk(task: str, predicted: str, band: str | None) -> str:
    if task == "binary_anomaly":
        return BINARY_TO_RISK[predicted]
    if task == "multiclass_risk":
        return predicted
    if band is None:
        raise ValueError("unsupervised band is missing")
    return band


def _band(score: float, quantiles: np.ndarray) -> str:
    if score <= quantiles[0]:
        return "LOW"
    if score <= quantiles[1]:
        return "MEDIUM"
    if score <= quantiles[2]:
        return "HIGH"
    return "CRITICAL"


def _scale(
    train: np.ndarray, test: np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    median = np.median(train, axis=0)
    mad = np.median(np.abs(train - median), axis=0)
    scale = np.where(mad > 0, mad, 1.0)
    return (train - median) / scale, (test - median) / scale, median, scale


def _top_text(
    encoder: FeatureEncoder, model: LogisticRegression, example: Example, predicted: str
) -> list[dict[str, object]]:
    if encoder.vectorizer is None:
        return []
    row = encoder.sparse_text([example])
    names = np.asarray(encoder.vectorizer.get_feature_names_out())
    class_index = list(model.classes_).index(predicted)
    if len(model.classes_) == 2:
        # Binary coef_ is a single row for classes_[1].
        weights = model.coef_[0] if predicted == model.classes_[1] else -model.coef_[0]
    else:
        weights = model.coef_[class_index]
    contribution = row.multiply(weights).toarray().ravel()
    order = np.argsort(contribution)[::-1][:5]
    reasons = []
    for index in order:
        value = float(contribution[index])
        if value <= 0:
            continue
        reasons.append({"term": str(names[index]), "contribution": value})
    return reasons


def _top_dense(
    names: list[str],
    values: np.ndarray,
    importances: np.ndarray,
) -> list[dict[str, object]]:
    score = np.abs(values) * importances
    order = np.argsort(score)[::-1][:5]
    rows = []
    for index in order:
        if float(score[index]) == 0:
            continue
        rows.append(
            {
                "feature": names[index],
                "value": float(values[index]),
                "importance": float(importances[index]),
            }
        )
    return rows


def _fit_supervised(algorithm: str, train: list[Example], seed: int):
    encoder = FeatureEncoder(seed)
    encoder.fit(train)
    y = [item.label for item in train]
    if algorithm == "tfidf_logreg":
        model = LogisticRegression(
            class_weight="balanced",
            max_iter=500,
            random_state=seed,
            solver="lbfgs",
        )
        model.fit(encoder.sparse_text(train), y)
        return encoder, model
    model = RandomForestClassifier(
        n_estimators=FOREST_ESTIMATORS,
        max_depth=24,
        class_weight="balanced",
        random_state=seed,
        n_jobs=1,
    )
    model.fit(encoder.dense(train), y)
    return encoder, model


def _predict_supervised(
    algorithm: str,
    encoder: FeatureEncoder,
    model,
    examples: list[Example],
    task: str,
    split_role: str,
) -> tuple[list[ScoredExample], np.ndarray, list[str]]:
    if algorithm == "tfidf_logreg":
        matrix = encoder.sparse_text(examples)
        predicted = model.predict(matrix)
        probability = model.predict_proba(matrix)
    else:
        matrix = encoder.dense(examples)
        predicted = model.predict(matrix)
        probability = model.predict_proba(matrix)
    classes = [str(label) for label in model.classes_]
    scored: list[ScoredExample] = []
    dense = encoder.dense(examples)
    names = encoder.feature_names()
    importances = (
        model.feature_importances_ if algorithm == "random_forest" else np.zeros(len(names))
    )
    for index, item in enumerate(examples):
        label = str(predicted[index])
        class_index = classes.index(label)
        confidence = float(probability[index, class_index])
        if algorithm == "tfidf_logreg":
            reasons = _top_text(encoder, model, item, label)
            summary = (
                f"TF-IDF logistic regression predicted {label} "
                f"with class probability {confidence:.3f}."
            )
        else:
            reasons = _top_dense(names, dense[index], importances)
            summary = f"Random Forest predicted {label} with class probability {confidence:.3f}."
        if task == "binary_anomaly":
            summary += " Display risk maps normal to LOW and anomaly to HIGH."
        scored.append(
            ScoredExample(
                example=item,
                predicted_label=label,
                predicted_risk=_display_risk(task, label, None),
                class_confidence=confidence,
                anomaly_score=None,
                score_kind="class_probability",
                explanation={
                    "summary": summary,
                    "reasons": reasons,
                    "content": item.content[:500],
                    "timestamp": None if item.timestamp is None else item.timestamp.isoformat(),
                    "label_kind": "model_prediction",
                },
                split_role=split_role,
            )
        )
    return scored, probability, classes


def _anomaly_scores(model: IsolationForest, matrix: np.ndarray) -> np.ndarray:
    # sklearn's decision function is higher for normal points. Flip it.
    return -model.decision_function(matrix)


def _fit_forest(train: list[Example], test: list[Example], seed: int):
    encoder = FeatureEncoder(seed)
    encoder.fit(train)
    train_dense = encoder.dense(train)
    test_dense = encoder.dense(test)
    scaled_train, scaled_test, median, scale = _scale(train_dense, test_dense)
    forest = IsolationForest(
        n_estimators=ISOLATION_ESTIMATORS,
        contamination=ISOLATION_CONTAMINATION,
        random_state=seed,
        n_jobs=1,
    )
    forest.fit(scaled_train)
    train_scores = _anomaly_scores(forest, scaled_train)
    test_scores = _anomaly_scores(forest, scaled_test)
    quantiles = np.quantile(train_scores, BAND_QUANTILES)
    return encoder, forest, test_scores, quantiles, median, scale, test_dense


def _score_forest(
    examples: list[Example],
    scores: np.ndarray,
    quantiles: np.ndarray,
    dense: np.ndarray,
    median: np.ndarray,
    scale: np.ndarray,
    names: list[str],
    split_role: str,
    task: str,
) -> tuple[list[ScoredExample], list[str], np.ndarray]:
    native: list[str] = []
    scored: list[ScoredExample] = []
    for index, item in enumerate(examples):
        score = float(scores[index])
        band = _band(score, quantiles)
        native_label = "anomaly" if score > 0 else "normal"
        native.append(native_label)
        z = (dense[index] - median) / scale
        order = np.argsort(np.abs(z))[::-1][:5]
        reasons = [
            {"feature": names[int(pos)], "robust_z": float(z[int(pos)])}
            for pos in order
            if float(z[int(pos)]) != 0
        ]
        if task == "unsupervised_band":
            predicted = band
            summary = (
                f"Isolation Forest anomaly score {score:.3f} falls in the {band} "
                "training-quantile band. The score is not a class probability."
            )
        else:
            predicted = native_label
            summary = (
                f"Isolation Forest anomaly score {score:.3f}. "
                "A score above 0 is the fixed contamination offset, not a tuned threshold. "
                f"Display risk maps this to {BINARY_TO_RISK[native_label]}."
            )
        scored.append(
            ScoredExample(
                example=item,
                predicted_label=predicted,
                predicted_risk=band
                if task == "unsupervised_band"
                else BINARY_TO_RISK[native_label],
                class_confidence=None,
                anomaly_score=score,
                score_kind="anomaly_score",
                explanation={
                    "summary": summary,
                    "reasons": reasons,
                    "content": item.content[:500],
                    "timestamp": None if item.timestamp is None else item.timestamp.isoformat(),
                    "label_kind": "model_prediction",
                    "band_quantiles": [float(value) for value in quantiles],
                },
                split_role=split_role,
            )
        )
    return scored, native, scores


def _cv_supervised(algorithm: str, train: list[Example], task: str, seed: int) -> dict[str, Any]:
    capped = cap_examples(train, CV_CAP, seed)
    y = [item.label for item in capped]
    groups = [item.group_key for item in capped]
    class_groups: dict[str, set[str]] = defaultdict(set)
    for label, group in zip(y, groups, strict=True):
        if label is not None:
            class_groups[label].add(group)
    if len(class_groups) < 2 or any(len(value) < CV_FOLDS for value in class_groups.values()):
        return {
            "folds": 0,
            "scope": "training groups only",
            "note": (
                "Cross-validation skipped because a class has fewer training groups than folds."
            ),
        }
    splitter = StratifiedGroupKFold(n_splits=CV_FOLDS, shuffle=True, random_state=seed)
    accuracies: list[float] = []
    f1_scores: list[float] = []
    blank = np.zeros(len(capped))
    try:
        folds = list(splitter.split(blank, y, groups))
    except ValueError as exc:
        return {
            "folds": 0,
            "scope": "training groups only",
            "note": f"Cross-validation skipped: {exc}",
        }
    for train_index, test_index in folds:
        fold_train = [capped[int(index)] for index in train_index]
        fold_test = [capped[int(index)] for index in test_index]
        encoder, model = _fit_supervised(algorithm, fold_train, seed)
        predicted, probability, classes = _predict_supervised(
            algorithm, encoder, model, fold_test, task, "train"
        )
        scores, columns = _metric_scores(task, probability, classes)
        result = classification_metrics(
            [item.example.label or "" for item in predicted],
            [item.predicted_label for item in predicted],
            labels=_labels_for(task),
            scores=scores,
            score_columns=columns,
        )
        if result["metrics"] is None:
            continue
        accuracies.append(result["metrics"]["accuracy"])
        f1_scores.append(result["metrics"]["f1_macro"])
    if not accuracies:
        return {
            "folds": 0,
            "scope": "training groups only",
            "note": "Cross-validation folds did not contain both classes.",
        }
    return {
        "folds": len(accuracies),
        "accuracy_mean": float(np.mean(accuracies)),
        "f1_macro_mean": float(np.mean(f1_scores)),
        "n_examples": len(capped),
        "scope": "training groups only",
        "note": (
            "These means are model-selection diagnostics. They are not the held-out test score."
        ),
    }


def _count_label(examples: list[Example], label: str) -> int:
    return sum(1 for item in examples if item.label == label)


def compare_models(
    examples: list[Example],
    *,
    task: str,
    seed: int,
    algorithms: tuple[str, ...] = ("isolation_forest", "random_forest", "tfidf_logreg"),
) -> list[ModelRun]:
    """Fit each requested algorithm. Test groups are scored once."""
    labeled = [item for item in examples if item.label]
    if task == "unsupervised_band":
        working = list(examples)
        split = split_groups(working, test_fraction=TEST_FRACTION, seed=seed)
        return [
            _run_forest(
                split.train,
                split.test,
                task=task,
                seed=seed,
                protocol=split.protocol,
                protocol_note=split.note,
                evaluate=False,
            )
        ]

    if task not in {"binary_anomaly", "multiclass_risk"}:
        raise ValueError(f"unknown task {task}")
    if len(labeled) != len(examples):
        raise ValueError("supervised comparison requires a label on every example")

    positive_groups = positive_group_count(labeled, "anomaly") if task == "binary_anomaly" else 2
    runs: list[ModelRun] = []
    if task == "binary_anomaly" and positive_groups < 2:
        try:
            held = holdout_positive_groups(labeled, positive="anomaly", seed=seed)
        except ValueError as exc:
            detail = str(exc)
            return [_refused(algorithm, task, detail) for algorithm in algorithms]
        train = cap_examples(held.train, TRAIN_CAP, seed)
        test = cap_examples(held.test, TEST_CAP, seed + 1)
        if "isolation_forest" in algorithms:
            runs.append(
                _run_forest(
                    train,
                    test,
                    task=task,
                    seed=seed,
                    protocol=held.protocol,
                    protocol_note=held.note,
                    evaluate=True,
                )
            )
        detail = (
            "The positive class collapses to one normalized template group. "
            "A supervised model cannot be tested on that group without also training on it."
        )
        for algorithm in algorithms:
            if algorithm in _SUPERVISED:
                runs.append(_refused(algorithm, task, detail))
        return runs

    split = split_groups(labeled, test_fraction=TEST_FRACTION, seed=seed)
    train = cap_examples(split.train, TRAIN_CAP, seed)
    test = cap_examples(split.test, TEST_CAP, seed + 1)
    if split.train_groups & split.test_groups:
        raise RuntimeError("template group leaked across the split")
    for algorithm in algorithms:
        if algorithm == "isolation_forest":
            runs.append(
                _run_forest(
                    train,
                    test,
                    task=task,
                    seed=seed,
                    protocol=split.protocol,
                    protocol_note=split.note,
                    evaluate=True,
                )
            )
        else:
            runs.append(
                _run_supervised(
                    algorithm,
                    train,
                    test,
                    task=task,
                    seed=seed,
                    protocol=split.protocol,
                    protocol_note=split.note,
                )
            )
    return runs


def _refused(algorithm: str, task: str, detail: str) -> ModelRun:
    refused = not_evaluated(detail)
    return ModelRun(
        algorithm=algorithm,
        task=task,
        fit_protocol="not_fit",
        n_train=0,
        n_test=0,
        metrics_status=refused["status"],
        metrics_note=refused["metrics_note"],
        detail=refused["detail"],
        metrics=None,
        cv={"folds": 0, "scope": "training groups only", "note": detail},
    )


def _run_supervised(
    algorithm: str,
    train: list[Example],
    test: list[Example],
    *,
    task: str,
    seed: int,
    protocol: str,
    protocol_note: str,
) -> ModelRun:
    train_labels = {item.label for item in train}
    if len(train_labels) < 2:
        return _refused(algorithm, task, "Training groups contain one class.")
    cv = _cv_supervised(algorithm, train, task, seed)
    encoder, model = _fit_supervised(algorithm, train, seed)
    predicted, probability, classes = _predict_supervised(
        algorithm, encoder, model, test, task, "test"
    )
    scores, columns = _metric_scores(task, probability, classes)
    result = classification_metrics(
        [item.example.label or "" for item in predicted],
        [item.predicted_label for item in predicted],
        labels=_labels_for(task),
        scores=scores,
        score_columns=columns,
    )
    positive = "anomaly" if task == "binary_anomaly" else "HIGH"
    return ModelRun(
        algorithm=algorithm,
        task=task,
        fit_protocol=protocol,
        n_train=len(train),
        n_test=len(test),
        metrics_status=result["status"],
        metrics_note=result["metrics_note"],
        detail=result["detail"] or protocol_note,
        metrics=_with_counts(result["metrics"], train, test, positive),
        cv=cv,
        predictions=predicted,
        bundle={
            "algorithm": algorithm,
            "task": task,
            "encoder": encoder,
            "model": model,
            "train_groups": sorted({item.group_key for item in train}),
            "protocol": protocol_note,
        },
    )


def _metric_scores(
    task: str,
    probability: np.ndarray,
    classes: list[str],
) -> tuple[np.ndarray | None, list[str] | None]:
    if task == "binary_anomaly":
        if "anomaly" not in classes:
            return None, None
        return probability[:, classes.index("anomaly")], None
    return probability, classes


def _run_forest(
    train: list[Example],
    test: list[Example],
    *,
    task: str,
    seed: int,
    protocol: str,
    protocol_note: str,
    evaluate: bool,
) -> ModelRun:
    encoder, _forest, test_scores, quantiles, median, scale, test_dense = _fit_forest(
        train, test, seed
    )
    scored, native, scores = _score_forest(
        test,
        test_scores,
        quantiles,
        test_dense,
        median,
        scale,
        encoder.feature_names(),
        "test",
        task,
    )
    if not evaluate:
        refused = not_evaluated(
            "Unsupervised score bands have no verified labels to score against."
        )
        return ModelRun(
            algorithm="isolation_forest",
            task=task,
            fit_protocol=protocol,
            n_train=len(train),
            n_test=len(test),
            metrics_status="not_evaluated",
            metrics_note=refused["metrics_note"],
            detail=refused["detail"],
            metrics=None,
            cv={
                "folds": 0,
                "scope": "training groups only",
                "note": "Isolation Forest is unsupervised.",
            },
            predictions=scored,
            bundle={"quantiles": [float(value) for value in quantiles], "protocol": protocol_note},
        )
    result = classification_metrics(
        [item.label or "" for item in test],
        native,
        labels=list(BINARY_LABELS) if task == "binary_anomaly" else _labels_for(task),
        scores=scores if task == "binary_anomaly" else None,
    )
    if task != "binary_anomaly":
        # Four-level bands are not the dataset's classes. Do not score them as such.
        refused = not_evaluated(
            "Isolation Forest bands are a quantile policy, not a trained four-class model."
        )
        result = refused
    return ModelRun(
        algorithm="isolation_forest",
        task=task,
        fit_protocol=protocol,
        n_train=len(train),
        n_test=len(test),
        metrics_status=result["status"],
        metrics_note=result["metrics_note"],
        detail=result["detail"] or protocol_note,
        metrics=_with_counts(result["metrics"], train, test, "anomaly"),
        cv={
            "folds": 0,
            "scope": "training groups only",
            "note": "Isolation Forest is unsupervised and has no training cross-validation.",
        },
        predictions=scored,
        bundle={
            "algorithm": "isolation_forest",
            "task": task,
            "encoder": encoder,
            "model": _forest,
            "median": median,
            "scale": scale,
            "quantiles": quantiles,
            "train_groups": sorted({item.group_key for item in train}),
            "protocol": protocol_note,
        },
    )


def fit_linux_bands(examples: list[Example], seed: int) -> ModelRun:
    """Fit Isolation Forest on training template groups and band every example.

    The bands are a display policy. They are not a verified risk label.
    """
    split = split_groups(examples, test_fraction=TEST_FRACTION, seed=seed)
    encoder = FeatureEncoder(seed)
    encoder.fit(split.train)
    train_dense = encoder.dense(split.train)
    test_dense = encoder.dense(split.test)
    scaled_train, scaled_test, median, scale = _scale(train_dense, test_dense)
    forest = IsolationForest(
        n_estimators=ISOLATION_ESTIMATORS,
        contamination=ISOLATION_CONTAMINATION,
        random_state=seed,
        n_jobs=1,
    )
    forest.fit(scaled_train)
    quantiles = np.quantile(_anomaly_scores(forest, scaled_train), BAND_QUANTILES)
    names = encoder.feature_names()
    train_scored, _, _ = _score_forest(
        split.train,
        _anomaly_scores(forest, scaled_train),
        quantiles,
        train_dense,
        median,
        scale,
        names,
        "train",
        "unsupervised_band",
    )
    test_scored, _, _ = _score_forest(
        split.test,
        _anomaly_scores(forest, scaled_test),
        quantiles,
        test_dense,
        median,
        scale,
        names,
        "test",
        "unsupervised_band",
    )
    refused = not_evaluated(
        "Linux log risk bands are unsupervised. Loghub Linux has no verified risk labels."
    )
    return ModelRun(
        algorithm="isolation_forest",
        task="unsupervised_band",
        fit_protocol=split.protocol,
        n_train=len(split.train),
        n_test=len(split.test),
        metrics_status="not_evaluated",
        metrics_note=refused["metrics_note"],
        detail=refused["detail"],
        metrics=None,
        cv={
            "folds": 0,
            "scope": "training groups only",
            "note": "Isolation Forest is unsupervised and has no training cross-validation.",
        },
        predictions=train_scored + test_scored,
        bundle={
            "algorithm": "isolation_forest",
            "task": "unsupervised_band",
            "encoder": encoder,
            "model": forest,
            "median": median,
            "scale": scale,
            "quantiles": quantiles,
            "train_groups": sorted(split.train_groups),
            "protocol": split.note,
        },
    )


def _with_counts(
    metrics: dict[str, Any] | None, train: list[Example], test: list[Example], positive: str
):
    if metrics is None:
        return None
    metrics = dict(metrics)
    metrics["n_train"] = len(train)
    metrics["n_test"] = len(test)
    metrics["n_train_positive"] = _count_label(train, positive)
    metrics["n_test_positive"] = _count_label(test, positive)
    metrics["train_label_counts"] = dict(Counter(item.label for item in train))
    metrics["test_label_counts"] = dict(Counter(item.label for item in test))
    return metrics
