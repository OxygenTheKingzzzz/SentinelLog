"""Naturally distributed and chronological evaluations.

This module does not replace published_results.json. Groups are assigned before
sampling. Thresholds are chosen on validation rows only.
"""

import csv
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from sentinellog.risk.constants import (
    FOREST_ESTIMATORS,
    ISOLATION_CONTAMINATION,
    ISOLATION_ESTIMATORS,
    NOT_EVALUATED,
    RANDOM_SEED,
)
from sentinellog.risk.datasets import (
    _hdfs_content,
    file_sha256,
    iter_bgl_zip,
    load_hadoop,
    load_openstack,
    parse_ras_line,
)
from sentinellog.risk.features import FeatureEncoder
from sentinellog.risk.metrics import classification_metrics
from sentinellog.risk.prevalence import (
    Catalog,
    Reservoir,
    assign_splits,
    calibration_report,
    chronological_reason,
    false_positives_per_thousand,
    near_duplicate_report,
    positive_groups,
    prevalence,
    select_f1_threshold,
    uniform_cap,
)
from sentinellog.risk.records import Example
from sentinellog.risk.textnorm import group_key, normalize_template

TRAIN_CAP = 20_000
VAL_CAP = 8_000
TEST_CAP = 20_000
PROBABILITY_DEFAULT = 0.5
SCORE_DEFAULT = 0.0
_EVENT_ID = re.compile(r"E\d+")
_CAPS = {"train": TRAIN_CAP, "validation": VAL_CAP, "test": TEST_CAP}

_BINARY_NOTE = (
    "Scores are binary normal versus anomaly. They do not validate "
    "LOW, MEDIUM, HIGH, or CRITICAL severity."
)


def evaluate_directory(root: Path) -> dict[str, Any]:
    experiments: list[dict[str, Any]] = []
    bgl = root / "BGL.zip"
    if bgl.is_file():
        print("bgl catalog", flush=True)
        experiments.append(_run_bgl(bgl))
    hdfs_label = root / "hdfs-preprocessed" / "preprocessed" / "anomaly_label.csv"
    hdfs_traces = root / "hdfs-preprocessed" / "preprocessed" / "Event_traces.csv"
    if hdfs_label.is_file() and hdfs_traces.is_file():
        print("hdfs catalog", flush=True)
        experiments.append(_run_hdfs(hdfs_label, hdfs_traces))
    if (root / "anomaly_labels.txt").is_file():
        print("openstack", flush=True)
        experiments.append(_run_openstack(root))
    hadoop = root / "Hadoop.zip"
    if hadoop.is_file():
        print("hadoop", flush=True)
        experiments.append(_run_hadoop(hadoop))
    thunderbird = root / "Thunderbird_2k.log"
    if thunderbird.is_file():
        print("thunderbird", flush=True)
        experiments.append(_run_thunderbird(thunderbird))
    experiments.append(_linux())
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "sentinellog.risk.realistic",
        "seed": RANDOM_SEED,
        "preserved_benchmark": "src/sentinellog/risk/published_results.json",
        "protocol": (
            "Template groups are assigned to train, validation, and test before sampling, "
            "feature fitting, or threshold selection. Row caps are uniform inside one side, "
            "so they keep that side's anomaly prevalence. The validation side chooses the "
            "threshold. The test side is scored once. Hyperparameters stay at the benchmark values."
        ),
        "experiments": experiments,
    }


def _linux() -> dict[str, Any]:
    return {
        "dataset": "linux",
        "dataset_version": "loghub-Linux_2k",
        "label_unit": "line",
        "label_provenance": "none",
        "label_definition": "Loghub's dataset table leaves Linux unlabeled.",
        "metrics_note": NOT_EVALUATED,
        "real_world": False,
        "detail": (
            "Linux_2k has no verified ground truth. LOW, MEDIUM, HIGH, and CRITICAL "
            "are estimated anomaly-score bands, not validated four-class severity."
        ),
        "protocols": [],
    }


def _run_bgl(path: Path) -> dict[str, Any]:
    catalog = Catalog()
    for number, line in enumerate(iter_bgl_zip(path), start=1):
        catalog.rows_seen += 1
        parts = line.split(None, 9)
        parsed = parse_ras_line(line, number, "bgl")
        if parsed is None or parsed.label is None or len(parts) < 10:
            catalog.skipped += 1
            continue
        token, message = parts[0], parts[9]
        if parsed.label == "anomaly" and token.lower() in message.lower():
            catalog.alert_token_in_body += 1
        catalog.observe(
            key=parsed.group_key,
            signature=normalize_template(parsed.content),
            label=parsed.label,
            timestamp=parsed.timestamp,
            severity=parsed.severity_rank,
        )
    meta = _meta(
        "bgl",
        "loghub-zenodo-8196385-BGL.zip",
        "https://zenodo.org/records/8196385/files/BGL.zip?download=1",
        file_sha256(path),
        "line",
        (
            "The first whitespace-separated token is the published BGL alert label. "
            "'-' is normal. That token is removed before the template and the features."
        ),
        catalog,
        features_available=[
            "component, level word, and message text",
            "severity rank from the level word and keywords",
            "hour sine and cosine",
            "template and component rarity fit on the training rows only",
        ],
        features_excluded=["alert token", "node name", "raw unix timestamp", "line number"],
    )
    return _finish_stream(meta, catalog, lambda assignment: _sample_bgl(path, assignment))


def _sample_bgl(
    path: Path, assignments: dict[str, dict[str, str]]
) -> dict[str, dict[str, list[Example]]]:
    buckets = _reservoirs(assignments)
    for number, line in enumerate(iter_bgl_zip(path), start=1):
        parsed = parse_ras_line(line, number, "bgl")
        if parsed is None or parsed.label is None:
            continue
        _offer(buckets, assignments, parsed)
    return _materialize(buckets)


def _run_hdfs(label_csv: Path, traces_csv: Path) -> dict[str, Any]:
    labels: dict[str, str] = {}
    with label_csv.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            native = row["Label"].strip().lower()
            if native in {"normal", "anomaly"}:
                labels[row["BlockId"]] = native
    csv.field_size_limit(10_000_000)
    catalog = Catalog()
    catalog.rows_seen = len(labels)

    def consume(
        collect: dict[str, dict[str, Reservoir]] | None,
        assignments: dict[str, dict[str, str]] | None,
    ):
        with traces_csv.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                native = labels.get(row["BlockId"])
                if native is None:
                    continue
                content = _hdfs_content(row.get("Features", ""))
                example = Example(
                    key=row["BlockId"],
                    content=content,
                    group_key=group_key(content),
                    timestamp=None,
                    component="hdfs.block",
                    pid=None,
                    severity_rank=0,
                    label=native,
                )
                if collect is None:
                    if row["BlockId"].lower() in content.lower():
                        catalog.identifier_in_features += 1
                    catalog.observe(
                        key=example.group_key,
                        signature=normalize_template(content),
                        label=native,
                        timestamp=None,
                        severity=0,
                    )
                else:
                    assert assignments is not None
                    _offer(collect, assignments, example)

    consume(None, None)
    meta = _meta(
        "hdfs",
        "loghub-zenodo-8196385-HDFS_v1",
        "https://zenodo.org/records/8196385/files/HDFS_v1.zip?download=1",
        file_sha256(label_csv),
        "block",
        (
            "anomaly_label.csv supplies Normal or Anomaly for a block. "
            "Features are the event-id sequence. Success/Fail, latency, and BlockId are excluded."
        ),
        catalog,
        features_available=["event-id sequence from Event_traces Features"],
        features_excluded=["BlockId", "Success/Fail", "Type", "TimeInterval", "Latency"],
    )
    meta["population"]["labeled_blocks"] = len(labels)
    return _finish_stream(meta, catalog, lambda assignment: _sample_hdfs(consume, assignment))


def _sample_hdfs(consume, assignments: dict[str, dict[str, str]]):
    buckets = _reservoirs(assignments)
    consume(buckets, assignments)
    return _materialize(buckets)


def _run_openstack(directory: Path) -> dict[str, Any]:
    examples, base = load_openstack(directory)
    anomalous = {
        line.strip()
        for line in (directory / "anomaly_labels.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    def identifier(item: Example) -> bool:
        return item.key.lower() in item.content.lower() or any(
            value.lower() in item.content.lower() for value in anomalous if len(value) > 8
        )

    return _run_memory(
        examples,
        _memory_meta(base, examples, identifier),
        feature_note=(
            "Each instance is one example. At most 40 normalized lines are kept per instance "
            "before the instance groups are split. Instance ids are replaced with <*>."
        ),
    )


def _run_hadoop(path: Path) -> dict[str, Any]:
    examples, base = load_hadoop(path)

    def identifier(item: Example) -> bool:
        return item.key.lower() in item.content.lower()

    meta = _memory_meta(base, examples, identifier)
    meta["feature_note"] = (
        "Each labeled application is one example. At most 80 normalized lines are kept "
        "from that application before the application groups are split. Application ids "
        "are numeric and are replaced before grouping."
    )
    return _run_memory(examples, meta, feature_note=str(meta["feature_note"]))


def _run_thunderbird(path: Path) -> dict[str, Any]:
    examples: list[Example] = []
    catalog = Catalog()
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for number, line in enumerate(text, start=1):
        catalog.rows_seen += 1
        parts = line.split(None, 9)
        parsed = parse_ras_line(line, number, "thunderbird")
        if parsed is None or parsed.label is None or len(parts) < 10:
            catalog.skipped += 1
            continue
        if parsed.label == "anomaly" and parts[0].lower() in parts[9].lower():
            catalog.alert_token_in_body += 1
        catalog.observe(
            key=parsed.group_key,
            signature=normalize_template(parsed.content),
            label=parsed.label,
            timestamp=parsed.timestamp,
            severity=parsed.severity_rank,
        )
        examples.append(parsed)
    meta = _meta(
        "thunderbird",
        "loghub-Thunderbird_2k",
        "https://raw.githubusercontent.com/logpai/loghub/master/Thunderbird/Thunderbird_2k.log",
        file_sha256(path),
        "line",
        (
            "Thunderbird uses the same first-token alert label as BGL. "
            "This file is the 2,000-line sample, not the full corpus."
        ),
        catalog,
        features_available=["component, level word, and message text"],
        features_excluded=["alert token"],
    )
    meta["examples"] = examples
    return _finish_memory(meta, catalog, examples)


def _run_memory(examples: list[Example], meta: dict[str, Any], feature_note: str) -> dict[str, Any]:
    catalog = Catalog()
    for item in examples:
        if item.label is None:
            catalog.skipped += 1
            continue
        catalog.rows_seen += 1
        catalog.observe(
            key=item.group_key,
            signature=normalize_template(item.content),
            label=item.label,
            timestamp=item.timestamp,
            severity=item.severity_rank,
        )
    meta = {
        **meta,
        "population": _population(catalog),
        "mixed_label_groups": _mixed(catalog),
        "feature_note": feature_note,
    }
    return _finish_memory(meta, catalog, [item for item in examples if item.label])


def _memory_meta(base: dict[str, Any], examples: list[Example], identifier) -> dict[str, Any]:
    leaked = sum(1 for item in examples if identifier(item))
    return {
        "dataset": base["dataset"],
        "dataset_version": base["dataset_version"],
        "source_url": base.get("source_url"),
        "file_sha256": base.get("file_sha256"),
        "label_unit": base["label_unit"],
        "label_provenance": base["label_provenance"],
        "label_definition": base["label_definition"],
        "leakage": {
            "identifier_in_features": leaked,
            "features_available": ["normalized log text for one instance or application"],
            "features_excluded": ["raw instance or application id"],
        },
    }


def _finish_stream(meta: dict[str, Any], catalog: Catalog, sample) -> dict[str, Any]:
    assignments = _assignments(catalog)
    print(f"{meta['dataset']} sampling", flush=True)
    sampled = sample(assignments)
    return _package(meta, catalog, assignments, sampled)


def _finish_memory(
    meta: dict[str, Any], catalog: Catalog, examples: list[Example]
) -> dict[str, Any]:
    assignments = _assignments(catalog)
    sampled: dict[str, dict[str, list[Example]]] = {}
    for name, assignment in assignments.items():
        if assignment is None:
            continue
        roles = assignment["roles"]
        sampled[name] = {}
        for role, cap in _CAPS.items():
            rows = [item for item in examples if roles[item.group_key] == role]
            sampled[name][role] = uniform_cap(rows, cap, RANDOM_SEED + _seed_offset(name, role))
    return _package(meta, catalog, assignments, sampled)


def _package(meta, catalog, assignments, sampled) -> dict[str, Any]:
    protocols = []
    chrono_reason = chronological_reason(catalog)
    anomaly_rows = sum(stat.anomaly for stat in catalog.groups.values())
    normal_rows = sum(stat.normal for stat in catalog.groups.values())
    groups_with_anomaly = sum(1 for stat in catalog.groups.values() if stat.anomaly)
    both_classes = anomaly_rows > 0 and normal_rows > 0
    single_positive = groups_with_anomaly < 2
    for name in ("realistic_group", "chronological_group"):
        assignment = assignments.get(name)
        if name == "chronological_group" and chrono_reason is not None:
            protocols.append(
                {
                    "name": name,
                    "meaningful": False,
                    "reason": chrono_reason,
                    "models": [],
                    "baselines": [],
                }
            )
            continue
        if not both_classes:
            protocols.append(
                _empty_protocol(
                    name,
                    "The labeled rows do not contain both classes, so accuracy is not computed.",
                )
            )
            continue
        assert assignment is not None
        print(f"{meta['dataset']} {name}", flush=True)
        protocols.append(
            _evaluate_protocol(
                name,
                assignment,
                sampled[name],
                catalog,
                single_positive=single_positive,
                event_baseline=meta["dataset"] == "hdfs",
                severity_baseline=meta["dataset"] in {"bgl", "thunderbird", "hadoop"},
            )
        )
    meta.pop("examples", None)
    meta["positive_template_groups"] = positive_groups(catalog)
    meta["mixed_label_groups"] = _mixed(catalog)
    meta["protocols"] = protocols
    return meta


def _assignments(catalog: Catalog) -> dict[str, dict[str, Any] | None]:
    realistic = assign_splits(catalog, mode="stratified", seed=RANDOM_SEED)
    if chronological_reason(catalog) is None and len(catalog.groups) >= 3:
        chrono = assign_splits(catalog, mode="chronological", seed=RANDOM_SEED)
    else:
        chrono = None
    return {"realistic_group": realistic, "chronological_group": chrono}


def _evaluate_protocol(
    name: str,
    assignment: dict[str, Any],
    sampled: dict[str, list[Example]],
    catalog: Catalog,
    *,
    single_positive: bool,
    event_baseline: bool,
    severity_baseline: bool,
) -> dict[str, Any]:
    train = sampled["train"]
    validation = sampled["validation"]
    test = sampled["test"]
    _assert_isolated(train, validation, test)
    roles = assignment["roles"]
    duplicates = near_duplicate_report(
        _signatures(catalog, roles, "train"),
        _signatures(catalog, roles, "test"),
    )
    near_keys = set(duplicates.pop("near_keys"))
    refusal = None
    if single_positive:
        refusal = (
            "Fewer than two template groups contain any anomaly. "
            "A supervised model cannot be trained on that template and tested on a different one."
        )
    models = [
        _model_record(
            "isolation_forest",
            train,
            validation,
            test,
            near_keys,
            score_kind="anomaly_score",
            refusal=None,
        ),
        _model_record(
            "random_forest",
            train,
            validation,
            test,
            near_keys,
            score_kind="class_probability",
            refusal=refusal,
        ),
        _model_record(
            "tfidf_logreg",
            train,
            validation,
            test,
            near_keys,
            score_kind="class_probability",
            refusal=refusal,
        ),
    ]
    baselines = []
    if severity_baseline and refusal is None:
        baselines.append(_severity_baseline(train, validation, test))
    if event_baseline and refusal is None:
        baselines.append(_event_baseline(train, test))
    counts = assignment["counts"]
    anomaly_keys = [key for key, stat in catalog.groups.items() if stat.anomaly]
    placement = Counter(roles[key] for key in anomaly_keys)
    return {
        "name": name,
        "meaningful": True,
        "reason": assignment["note"],
        "stratified": assignment["stratified"],
        "full_split": counts,
        "evaluated_rows": {
            role: _row_prevalence(sampled[role]) for role in ("train", "validation", "test")
        },
        "span_overlap": assignment.get("span_overlap"),
        "anomaly_bearing_groups": len(anomaly_keys),
        "anomaly_group_placement": dict(placement),
        "near_duplicates": duplicates,
        "models": models,
        "baselines": [item for item in baselines if item is not None],
    }


def _model_record(
    algorithm: str,
    train: list[Example],
    validation: list[Example],
    test: list[Example],
    near_keys: set[str],
    *,
    score_kind: str,
    refusal: str | None,
) -> dict[str, Any]:
    if refusal:
        return _refused(algorithm, refusal, train, validation, test)
    if len({item.label for item in train}) < 2 and algorithm != "isolation_forest":
        return _refused(algorithm, "The training side contains one class.", train, validation, test)
    if not train or not test:
        return _refused(algorithm, "A split side is empty after sampling.", train, validation, test)
    default = SCORE_DEFAULT if score_kind == "anomaly_score" else PROBABILITY_DEFAULT
    val_scores, test_scores = _scores(algorithm, train, validation, test)
    chosen = select_f1_threshold([item.label or "" for item in validation], val_scores)
    threshold = default if chosen["value"] is None else float(chosen["value"])
    if chosen["value"] is None:
        chosen = {**chosen, "applied_value": default}
    else:
        chosen = {**chosen, "applied_value": threshold}
    operating = _point(test, test_scores, threshold)
    default_point = _point(test, test_scores, default)
    calibration = _calibrate(algorithm, validation, val_scores, test, test_scores)
    excluded = _exclude_near(test, test_scores, threshold, near_keys)
    status = operating["status"]
    return {
        "algorithm": algorithm,
        "score_kind": score_kind,
        "metrics_status": status,
        "metrics_note": operating["metrics_note"],
        "detail": operating["detail"] or _BINARY_NOTE,
        "real_world": status == "evaluated" and operating["metrics"] is not None,
        "n_train": len(train),
        "n_validation": len(validation),
        "n_test": len(test),
        "threshold": chosen,
        "default_threshold_value": default,
        "operating_point": operating["metrics"],
        "default_threshold": default_point["metrics"],
        "calibration": calibration,
        "near_duplicate_excluded": excluded,
        "hyperparameters_locked": True,
    }


def _scores(algorithm: str, train: list[Example], validation: list[Example], test: list[Example]):
    if algorithm == "isolation_forest":
        return _forest_scores(train, validation, test)
    encoder = FeatureEncoder(RANDOM_SEED)
    encoder.fit(train)
    labels = [item.label for item in train]
    if algorithm == "tfidf_logreg":
        model = LogisticRegression(
            class_weight="balanced",
            max_iter=500,
            random_state=RANDOM_SEED,
            solver="lbfgs",
        )
        model.fit(encoder.sparse_text(train), labels)
        val_matrix = encoder.sparse_text(validation) if validation else None
        test_matrix = encoder.sparse_text(test)
    else:
        model = RandomForestClassifier(
            n_estimators=FOREST_ESTIMATORS,
            max_depth=24,
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=1,
        )
        model.fit(encoder.dense(train), labels)
        val_matrix = encoder.dense(validation) if validation else None
        test_matrix = encoder.dense(test)
    val_scores = _positive_proba(model, val_matrix) if val_matrix is not None else np.asarray([])
    return val_scores, _positive_proba(model, test_matrix)


def _positive_proba(model, matrix) -> np.ndarray:
    classes = [str(label) for label in model.classes_]
    if "anomaly" not in classes:
        return np.zeros(matrix.shape[0], dtype=np.float64)
    return np.asarray(model.predict_proba(matrix)[:, classes.index("anomaly")], dtype=np.float64)


def _forest_scores(train: list[Example], validation: list[Example], test: list[Example]):
    encoder = FeatureEncoder(RANDOM_SEED)
    encoder.fit(train)
    train_dense = encoder.dense(train)
    median = np.median(train_dense, axis=0)
    mad = np.median(np.abs(train_dense - median), axis=0)
    scale = np.where(mad > 0, mad, 1.0)
    forest = IsolationForest(
        n_estimators=ISOLATION_ESTIMATORS,
        contamination=ISOLATION_CONTAMINATION,
        random_state=RANDOM_SEED,
        n_jobs=1,
    )
    forest.fit((train_dense - median) / scale)

    def score(rows: list[Example]) -> np.ndarray:
        if not rows:
            return np.asarray([], dtype=np.float64)
        dense = (encoder.dense(rows) - median) / scale
        return -forest.decision_function(dense)

    return score(validation), score(test)


def _point(test: list[Example], scores: np.ndarray, threshold: float) -> dict[str, Any]:
    if not test:
        return {
            "status": "not_evaluated",
            "metrics": None,
            "metrics_note": NOT_EVALUATED,
            "detail": "The scored rows are empty.",
        }
    labels = [item.label or "" for item in test]
    predicted = ["anomaly" if float(score) >= threshold else "normal" for score in scores]
    result = classification_metrics(
        labels,
        predicted,
        labels=["normal", "anomaly"],
        scores=scores,
    )
    if result["metrics"] is not None:
        matrix = result["metrics"]["confusion_matrix"]
        result["metrics"]["fp_per_1000_normal"] = false_positives_per_thousand(
            matrix["matrix"], matrix["labels"]
        )
        result["metrics"]["threshold"] = threshold
        result["metrics"]["prevalence"] = prevalence(
            sum(label == "normal" for label in labels),
            sum(label == "anomaly" for label in labels),
        )
        result["detail"] = _BINARY_NOTE
    return result


def _calibrate(algorithm, validation, val_scores, test, test_scores) -> dict[str, Any]:
    if algorithm == "isolation_forest":
        mapped = _platt(validation, val_scores, test_scores)
        if mapped is None:
            return {
                "ece": None,
                "brier": None,
                "note": (
                    "The raw Isolation Forest score is not a probability, "
                    "and validation could not fit a map."
                ),
            }
        report = calibration_report([item.label or "" for item in test], mapped)
        report["note"] = (
            "Platt scaling was fit on validation scores only. "
            "The raw Isolation Forest score is not a class probability."
        )
        return report
    report = calibration_report(test and [item.label or "" for item in test], test_scores)
    report["note"] = "Reliability of P(anomaly) on the test rows. The threshold was not used."
    return report


def _platt(validation: list[Example], val_scores: np.ndarray, test_scores: np.ndarray):
    if len(validation) < 2 or len({item.label for item in validation}) < 2:
        return None
    model = LogisticRegression(max_iter=200)
    model.fit(val_scores.reshape(-1, 1), [item.label for item in validation])
    classes = [str(label) for label in model.classes_]
    if "anomaly" not in classes:
        return None
    return model.predict_proba(test_scores.reshape(-1, 1))[:, classes.index("anomaly")]


def _exclude_near(test, scores, threshold, near_keys: set[str]) -> dict[str, Any]:
    if not near_keys:
        return {
            "excluded_groups": 0,
            "metrics": None,
            "note": "No test template reached Jaccard 0.8.",
        }
    kept_examples = []
    kept_scores = []
    for item, score in zip(test, scores, strict=True):
        if item.group_key not in near_keys:
            kept_examples.append(item)
            kept_scores.append(float(score))
    result = _point(kept_examples, np.asarray(kept_scores, dtype=np.float64), threshold)
    note = "Same model and validation threshold, with near-duplicate test templates removed."
    if not kept_examples:
        note = "Every evaluated test template met the near-duplicate cutoff."
    return {
        "excluded_groups": len(near_keys),
        "n_test": len(kept_examples),
        "metrics_status": result["status"],
        "metrics_note": result["metrics_note"],
        "metrics": result["metrics"],
        "note": note,
    }


def _severity_baseline(train, validation, test) -> dict[str, Any] | None:
    if len({item.label for item in train}) < 2:
        return None
    model = LogisticRegression(class_weight="balanced", max_iter=200)
    model.fit([[item.severity_rank] for item in train], [item.label for item in train])

    def score(rows: list[Example]) -> np.ndarray:
        if not rows:
            return np.asarray([], dtype=np.float64)
        return _positive_proba(model, [[item.severity_rank] for item in rows])

    val_scores = score(validation)
    test_scores = score(test)
    chosen = select_f1_threshold([item.label or "" for item in validation], val_scores)
    threshold = PROBABILITY_DEFAULT if chosen["value"] is None else float(chosen["value"])
    point = _point(test, test_scores, threshold)
    return {
        "name": "severity_rank_only",
        "detail": (
            "Logistic regression on the severity rank alone. "
            "The level word is available to the text models."
        ),
        "threshold": {**chosen, "applied_value": threshold},
        "metrics_status": point["status"],
        "metrics_note": point["metrics_note"],
        "operating_point": point["metrics"],
        "real_world": point["status"] == "evaluated",
    }


def _event_baseline(train: list[Example], test: list[Example]) -> dict[str, Any] | None:
    counts: dict[str, list[int]] = {}
    for item in train:
        seen = set(_EVENT_ID.findall(item.content))
        for token in seen:
            bucket = counts.setdefault(token, [0, 0])
            bucket[1 if item.label == "anomaly" else 0] += 1
    best_token = None
    best_precision = -1.0
    for token, (normal, anomaly) in counts.items():
        support = normal + anomaly
        if support < 30:
            continue
        precision = anomaly / support
        if precision > best_precision:
            best_precision = precision
            best_token = token
    if best_token is None:
        return None
    predicted = [
        "anomaly" if best_token in set(_EVENT_ID.findall(item.content)) else "normal"
        for item in test
    ]
    scores = np.asarray([1.0 if label == "anomaly" else 0.0 for label in predicted])
    result = classification_metrics(
        [item.label or "" for item in test],
        predicted,
        labels=["normal", "anomaly"],
        scores=scores,
    )
    if result["metrics"] is not None:
        matrix = result["metrics"]["confusion_matrix"]
        result["metrics"]["fp_per_1000_normal"] = false_positives_per_thousand(
            matrix["matrix"], matrix["labels"]
        )
    return {
        "name": "single_event_id",
        "token": best_token,
        "train_precision": best_precision,
        "detail": (
            "The event id with the highest train anomaly rate and at least 30 train rows. "
            "It was chosen on train only."
        ),
        "metrics_status": result["status"],
        "metrics_note": result["metrics_note"],
        "operating_point": result["metrics"],
        "real_world": result["status"] == "evaluated",
    }


def _refused(algorithm: str, detail: str, train, validation, test) -> dict[str, Any]:
    return {
        "algorithm": algorithm,
        "metrics_status": "not_evaluated",
        "metrics_note": NOT_EVALUATED,
        "detail": detail,
        "real_world": False,
        "n_train": len(train),
        "n_validation": len(validation),
        "n_test": len(test),
        "threshold": None,
        "operating_point": None,
        "default_threshold": None,
        "calibration": None,
        "near_duplicate_excluded": None,
        "hyperparameters_locked": True,
    }


def _empty_protocol(name: str, detail: str) -> dict[str, Any]:
    return {
        "name": name,
        "meaningful": True,
        "reason": detail,
        "models": [
            _refused(algorithm, detail, [], [], [])
            for algorithm in ("isolation_forest", "random_forest", "tfidf_logreg")
        ],
        "baselines": [],
        "full_split": None,
        "evaluated_rows": None,
        "near_duplicates": None,
    }


def _reservoirs(assignments: dict[str, dict[str, str]]) -> dict[str, dict[str, Reservoir]]:
    buckets: dict[str, dict[str, Reservoir]] = {}
    for name, assignment in assignments.items():
        if assignment is None:
            continue
        buckets[name] = {
            role: Reservoir(_CAPS[role], RANDOM_SEED + _seed_offset(name, role))
            for role in _CAPS
        }
    return buckets


def _offer(buckets, assignments, example: Example) -> None:
    for name, assignment in assignments.items():
        if assignment is None:
            continue
        role = assignment["roles"].get(example.group_key)
        if role is None:
            continue
        buckets[name][role].add(example)


def _materialize(buckets: dict[str, dict[str, Reservoir]]) -> dict[str, dict[str, list[Example]]]:
    return {
        name: {role: list(bucket.items) for role, bucket in roles.items()}
        for name, roles in buckets.items()
    }


def _seed_offset(name: str, role: str) -> int:
    return {"realistic_group": 0, "chronological_group": 20}[name] + {
        "train": 0,
        "validation": 1,
        "test": 2,
    }[role]


def _signatures(catalog: Catalog, roles: dict[str, str], role: str) -> list[tuple[str, str]]:
    return [
        (key, catalog.groups[key].signature)
        for key, assigned in roles.items()
        if assigned == role
    ]


def _assert_isolated(*sides: list[Example]) -> None:
    seen: set[str] = set()
    for side in sides:
        keys = {item.group_key for item in side}
        if seen & keys:
            raise RuntimeError("template group leaked across the split")
        seen |= keys


def _row_prevalence(rows: list[Example]) -> dict[str, object]:
    normal = sum(item.label == "normal" for item in rows)
    anomaly = sum(item.label == "anomaly" for item in rows)
    return {
        "rows": len(rows),
        "normal": normal,
        "anomaly": anomaly,
        "prevalence": prevalence(normal, anomaly),
        "groups": len({item.group_key for item in rows}),
    }


def _mixed(catalog: Catalog) -> int:
    return sum(1 for stat in catalog.groups.values() if stat.normal and stat.anomaly)


def _population(catalog: Catalog) -> dict[str, object]:
    normal = sum(stat.normal for stat in catalog.groups.values())
    anomaly = sum(stat.anomaly for stat in catalog.groups.values())
    return {
        "parsed": catalog.parsed,
        "skipped": catalog.skipped,
        "rows_seen": catalog.rows_seen,
        "normal": normal,
        "anomaly": anomaly,
        "prevalence": prevalence(normal, anomaly),
        "template_groups": len(catalog.groups),
    }


def _meta(
    dataset: str,
    version: str,
    url: str,
    digest: str,
    unit: str,
    definition: str,
    catalog: Catalog,
    *,
    features_available: list[str],
    features_excluded: list[str],
) -> dict[str, Any]:
    severity = []
    for rank, (normal, anomaly) in sorted(catalog.severity_counts.items()):
        severity.append(
            {
                "severity_rank": rank,
                "normal": normal,
                "anomaly": anomaly,
                "prevalence": prevalence(normal, anomaly),
            }
        )
    return {
        "dataset": dataset,
        "dataset_version": version,
        "source_url": url,
        "file_sha256": digest,
        "label_unit": unit,
        "label_provenance": "dataset_native",
        "label_definition": definition,
        "population": _population(catalog),
        "leakage": {
            "alert_token_in_message_body": catalog.alert_token_in_body,
            "anomaly_rows": catalog.anomaly_rows,
            "identifier_in_features": catalog.identifier_in_features,
            "severity_prevalence": severity,
            "features_available": features_available,
            "features_excluded": features_excluded,
        },
    }


def render_report(payload: dict[str, Any]) -> str:
    """Write the evaluation narrative from measured fields only."""
    lines = [
        "# Realistic prevalence and chronological evaluation",
        "",
        f"Generated {payload['generated_at']} by `{payload['generator']}` with seed {payload['seed']}.",  # noqa: E501
        "",
        payload["protocol"],
        "",
        "The original file `published_results.json` is unchanged. Its BGL and HDFS numbers come from a class round-robin sample and are a rebalanced benchmark, not a realistic-prevalence result.",  # noqa: E501
        "",
        "LOW, MEDIUM, HIGH, and CRITICAL on Linux are estimated score bands. Binary accuracy does not validate those four levels. Linux_2k stays unevaluated.",  # noqa: E501
        "",
        "## How each split was built",
        "",
        "Train, validation, and test each receive whole template groups. About 60% of groups go to train, 20% to validation, and 20% to test. A uniform reservoir then caps each side at 20,000 train rows, 8,000 validation rows, and 20,000 test rows. The cap does not rebalance classes. Feature vocabularies and the Isolation Forest are fit on train. The anomaly threshold maximizes anomaly F1 on validation, with ties broken toward higher precision and then a higher threshold. Test labels are used once, for the reported metrics.",  # noqa: E501
        "",
        "The chronological protocol orders templates by their earliest timestamp. It is omitted when timestamps are missing. A template that begins in the training window is never copied into the future test, even if that template continues to emit lines later. Those later lines remain in train. The report counts train templates whose span crosses the test boundary.",  # noqa: E501
        "",
        "Near-duplicates are token-Jaccard matches of at least 0.8 between a test template and a train template. Metrics with those test templates removed use the same fitted model and the same validation threshold.",  # noqa: E501
        "",
    ]
    for experiment in payload["experiments"]:
        lines.extend(_experiment_lines(experiment))
    lines.extend(
        [
            "## Deployment",
            "",
            _deployment(payload),
            "",
        ]
    )
    return "\n".join(lines)


def _experiment_lines(experiment: dict[str, Any]) -> list[str]:
    lines = [f"## {experiment['dataset']}", ""]
    if experiment.get("metrics_note") == NOT_EVALUATED and not experiment.get("protocols"):
        lines.append(experiment.get("detail") or NOT_EVALUATED)
        lines.append("")
        return lines
    population = experiment.get("population") or {}
    lines.append(
        f"Unit: {experiment.get('label_unit')}. {experiment.get('label_definition', '')}"
    )
    lines.append(
        "Population prevalence "
        f"{_fmt(population.get('prevalence'))} "
        f"({population.get('anomaly')} anomaly / {population.get('normal')} normal, "
        f"{population.get('template_groups')} template groups)."
    )
    if experiment.get("positive_template_groups") is not None:
        lines.append(
            f"Anomalous template groups: {experiment['positive_template_groups']}. "
            f"Groups that contain both labels: {experiment.get('mixed_label_groups')}."
        )
    leakage = experiment.get("leakage") or {}
    if leakage:
        lines.append(
            "Features available: " + "; ".join(leakage.get("features_available") or []) + "."
        )
        lines.append(
            "Features excluded: " + "; ".join(leakage.get("features_excluded") or []) + "."
        )
        lines.append(
            f"Alert-token copies inside the message body: {leakage.get('alert_token_in_message_body', 0)}. "  # noqa: E501
            f"Raw identifiers found inside features: {leakage.get('identifier_in_features', 0)}."
        )
        for row in leakage.get("severity_prevalence") or []:
            lines.append(
                f"Severity rank {row['severity_rank']}: anomaly prevalence {_fmt(row.get('prevalence'))} "  # noqa: E501
                f"({row['anomaly']} anomaly / {row['normal']} normal)."
            )
    note = experiment.get("feature_note")
    if note:
        lines.append(note)
    lines.append("")
    for protocol in experiment.get("protocols") or []:
        lines.extend(_protocol_lines(protocol))
    return lines


def _protocol_lines(protocol: dict[str, Any]) -> list[str]:
    lines = [f"### {protocol['name']}", ""]
    if not protocol.get("meaningful", True):
        lines.append(f"Not used. {protocol.get('reason')}")
        lines.append("")
        return lines
    lines.append(protocol.get("reason") or "")
    full = protocol.get("full_split") or {}
    if full:
        lines.append(
            "Full split before the row cap: "
            + "; ".join(
                f"{role} prevalence {_fmt((full.get(role) or {}).get('prevalence'))} "
                f"({(full.get(role) or {}).get('anomaly')} / {(full.get(role) or {}).get('rows')} rows)"  # noqa: E501
                for role in ("train", "validation", "test", "population")
                if full.get(role)
            )
            + "."
        )
    evaluated = protocol.get("evaluated_rows") or {}
    if evaluated:
        lines.append(
            "Evaluated rows: "
            + "; ".join(
                f"{role} {evaluated[role]['rows']} prevalence {_fmt(evaluated[role].get('prevalence'))}"  # noqa: E501
                for role in ("train", "validation", "test")
                if evaluated.get(role)
            )
            + "."
        )
    if protocol.get("anomaly_bearing_groups") is not None:
        lines.append(
            "Template groups that contain any anomaly: "
            f"{protocol['anomaly_bearing_groups']}. "
            f"Their split placement: {protocol.get('anomaly_group_placement')}."
        )
    overlap = protocol.get("span_overlap") or {}
    if overlap and overlap.get("train_groups_extending_into_test") is not None:
        lines.append(
            f"Train templates whose time span crosses the test boundary: "
            f"{overlap['train_groups_extending_into_test']}."
        )
    dup = protocol.get("near_duplicates") or {}
    if dup:
        lines.append(
            f"Near-duplicate test templates (Jaccard >= 0.8): {dup.get('jaccard_at_least_0_8')} "
            f"of {dup.get('test_groups')}. Jaccard >= 0.5: {dup.get('jaccard_at_least_0_5')}. "
            f"Median nearest-train Jaccard {_fmt(dup.get('median_max_jaccard'))}."
        )
    lines.append("")
    lines.append(
        "| Model | Status | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FP / 1,000 normal | Threshold |"  # noqa: E501
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for model in protocol.get("models") or []:
        lines.append(_model_row(model))
    for baseline in protocol.get("baselines") or []:
        lines.append(_model_row({**baseline, "algorithm": baseline.get("name")}))
    lines.append("")
    for model in protocol.get("models") or []:
        point = model.get("operating_point") or {}
        matrix = (point.get("confusion_matrix") or {}) if point else {}
        if matrix:
            lines.append(
                f"{model['algorithm']} confusion matrix {matrix.get('labels')}: {matrix.get('matrix')}."  # noqa: E501
            )
        calibration = model.get("calibration") or {}
        if calibration.get("ece") is not None:
            lines.append(
                f"{model['algorithm']} calibration ECE {_fmt(calibration.get('ece'))}, "
                f"Brier {_fmt(calibration.get('brier'))}. {calibration.get('note', '')}"
            )
        if not point:
            detail = model.get("detail")
            if detail and detail != model.get("metrics_note"):
                lines.append(f"{model['algorithm']}: {detail}")  # noqa: E501
        excluded = model.get("near_duplicate_excluded") or {}
        excluded_metrics = excluded.get("metrics") or {}
        if excluded_metrics:
            lines.append(
                f"{model['algorithm']} after removing near-duplicates: "
                f"F1 {_fmt(excluded_metrics.get('f1'))}, "
                f"precision {_fmt(excluded_metrics.get('precision'))}, "
                f"n={excluded.get('n_test')}."
            )
        elif excluded.get("note"):
            lines.append(
                f"{model['algorithm']} after removing near-duplicates: {excluded['note']} "  # noqa: E501
                f"n={excluded.get('n_test')}."
            )
        default_metrics = model.get("default_threshold") or {}
        if default_metrics and point:
            lines.append(
                f"{model['algorithm']} at the default threshold {model.get('default_threshold_value')}: "  # noqa: E501
                f"F1 {_fmt(default_metrics.get('f1'))}, "
                f"FP/1,000 {_fmt(default_metrics.get('fp_per_1000_normal'))}."
            )
    lines.append("")
    return lines


def _model_row(model: dict[str, Any]) -> str:
    point = model.get("operating_point") or {}
    if model.get("metrics_status") != "evaluated" or not point:
        note = model.get("metrics_note") or NOT_EVALUATED
        return f"| {model.get('algorithm')} | {note} | | | | | | | | |"
    threshold = (model.get("threshold") or {}).get("applied_value")
    return (
        f"| {model.get('algorithm')} | evaluated | {_fmt(point.get('accuracy'))} | "
        f"{_fmt(point.get('precision'))} | {_fmt(point.get('recall'))} | {_fmt(point.get('f1'))} | "
        f"{_fmt(point.get('roc_auc'))} | {_fmt(point.get('pr_auc'))} | "
        f"{_fmt(point.get('fp_per_1000_normal'))} | {_fmt(threshold)} |"
    )


def _fmt(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _find(payload: dict[str, Any], dataset: str) -> dict[str, Any] | None:
    return next((item for item in payload["experiments"] if item["dataset"] == dataset), None)


def _protocol(experiment: dict[str, Any] | None, name: str) -> dict[str, Any] | None:
    if experiment is None:
        return None
    return next((item for item in experiment.get("protocols") or [] if item["name"] == name), None)


def _fitted(protocol: dict[str, Any] | None, algorithm: str) -> dict[str, Any] | None:
    if protocol is None:
        return None
    return next(
        (item for item in protocol.get("models") or [] if item["algorithm"] == algorithm),
        None,
    )


def _op(model: dict[str, Any] | None) -> dict[str, Any]:
    if model is None:
        return {}
    return model.get("operating_point") or {}


def _benchmark_prevalence(dataset: str) -> str:
    path = Path(__file__).resolve().parent / "published_results.json"
    if not path.is_file():
        return "the preserved benchmark file"
    published = json.loads(path.read_text(encoding="utf-8"))
    experiment = next(
        (item for item in published.get("experiments") or [] if item.get("dataset") == dataset),
        None,
    )
    if experiment is None:
        return "the preserved benchmark file"
    forest = next(
        (
            item
            for item in experiment.get("models") or []
            if item.get("algorithm") == "random_forest" and item.get("real_world")
        ),
        None,
    )
    if forest is None or not forest.get("n_test"):
        return "the preserved benchmark file"
    metrics = forest.get("metrics") or {}
    positive = metrics.get("n_test_positive")
    if positive is None:
        return "the preserved benchmark file"
    prevalence = positive / forest["n_test"]
    return (
        f"random forest F1 {_fmt(metrics.get('f1'))} on a test set whose anomaly prevalence is "
        f"{_fmt(prevalence)} ({positive} of {forest['n_test']} rows)"
    )


def _deployment(payload: dict[str, Any]) -> str:
    """State what the measured tables support. Every figure is read from this run."""
    paragraphs = [
        (
            "These scores are normal versus anomaly. They do not validate LOW, MEDIUM, HIGH, "
            "or CRITICAL. Linux_2k has no verified labels, so its bands stay estimated score "
            "quantiles. A model is not a deployment candidate here unless a protocol with "
            "realistic prevalence, an untouched test set, and a check for near-duplicate "
            "templates still keeps false positives low."
        ),
        _bgl_support(_find(payload, "bgl")),
        _hdfs_support(_find(payload, "hdfs")),
        _openstack_support(_find(payload, "openstack")),
        _hadoop_support(_find(payload, "hadoop")),
        _thunderbird_support(_find(payload, "thunderbird")),
    ]
    return "\n\n".join(paragraph for paragraph in paragraphs if paragraph)


def _bgl_support(experiment: dict[str, Any] | None) -> str:
    random = _protocol(experiment, "realistic_group")
    chrono = _protocol(experiment, "chronological_group")
    if random is None or chrono is None:
        return ""
    population = (experiment or {}).get("population") or {}
    forest = _op(_fitted(random, "random_forest"))
    logistic = _op(_fitted(random, "tfidf_logreg"))
    isolation = _op(_fitted(random, "isolation_forest"))
    future_forest = _op(_fitted(chrono, "random_forest"))
    future_logistic = _op(_fitted(chrono, "tfidf_logreg"))
    future_isolation = _op(_fitted(chrono, "isolation_forest"))
    future_default = (_fitted(chrono, "isolation_forest") or {}).get("default_threshold") or {}
    dropped = (
        (_fitted(random, "random_forest") or {}).get("near_duplicate_excluded") or {}
    ).get("metrics") or {}
    near = chrono.get("near_duplicates") or {}
    severity = ((experiment or {}).get("leakage") or {}).get("severity_prevalence") or []
    anomaly_ranks = [row["severity_rank"] for row in severity if row.get("anomaly")]
    baseline = next(
        (
            item
            for item in random.get("baselines") or []
            if item.get("name") == "severity_rank_only"
        ),
        {},
    )
    base_point = baseline.get("operating_point") or {}
    if anomaly_ranks == [3]:
        severity_sentence = (
            "Every BGL anomaly in this parse has severity rank 3. "
            f"The severity-only baseline recalls {_fmt(base_point.get('recall'))} of anomalies "
            f"at precision {_fmt(base_point.get('precision'))} and FP/1,000 "
            f"{_fmt(base_point.get('fp_per_1000_normal'))}, below the text models on precision. "
        )
    else:
        severity_sentence = ""
    return (
        "BGL corpus prevalence is "
        f"{_fmt(population.get('prevalence'))}. The preserved benchmark reports "
        f"{_benchmark_prevalence('bgl')}. This run's random group holdout tests at prevalence "
        f"{_fmt(forest.get('prevalence'))}: random forest F1 {_fmt(forest.get('f1'))}, "
        f"precision {_fmt(forest.get('precision'))}, recall {_fmt(forest.get('recall'))}, "
        f"FP/1,000 normal {_fmt(forest.get('fp_per_1000_normal'))}; logistic regression F1 "
        f"{_fmt(logistic.get('f1'))} with FP/1,000 {_fmt(logistic.get('fp_per_1000_normal'))}. "
        f"Removing near-duplicate test templates drops random-forest F1 to {_fmt(dropped.get('f1'))}. "  # noqa: E501
        "The chronological holdout is the cleaner check: median nearest-train Jaccard is "
        f"{_fmt(near.get('median_max_jaccard'))}, random forest F1 {_fmt(future_forest.get('f1'))} "  # noqa: E501
        f"and logistic regression F1 {_fmt(future_logistic.get('f1'))}, with FP/1,000 "
        f"{_fmt(future_forest.get('fp_per_1000_normal'))} and "
        f"{_fmt(future_logistic.get('fp_per_1000_normal'))}. "
        f"Isolation Forest does not transfer. Its validation threshold scores F1 {_fmt(future_isolation.get('f1'))} "  # noqa: E501
        f"with FP/1,000 {_fmt(future_isolation.get('fp_per_1000_normal'))} on the future split, "
        f"while the default score threshold of 0 scores F1 {_fmt(future_default.get('f1'))} "
        f"and FP/1,000 {_fmt(future_default.get('fp_per_1000_normal'))}. "
        f"On the random split its F1 is {_fmt(isolation.get('f1'))}. "
        f"{severity_sentence}"
        "Chronological random forest and logistic regression are the only BGL results that "
        "look like generalization. They still do not validate four-class severity."
    )


def _hdfs_support(experiment: dict[str, Any] | None) -> str:
    protocol = _protocol(experiment, "realistic_group")
    chrono = _protocol(experiment, "chronological_group")
    if protocol is None:
        return ""
    population = (experiment or {}).get("population") or {}
    forest = _op(_fitted(protocol, "random_forest"))
    logistic = _op(_fitted(protocol, "tfidf_logreg"))
    isolation = _op(_fitted(protocol, "isolation_forest"))
    dropped = (
        (_fitted(protocol, "random_forest") or {}).get("near_duplicate_excluded") or {}
    ).get("metrics") or {}
    baseline = next(
        (item for item in protocol.get("baselines") or [] if item.get("name") == "single_event_id"),
        {},
    )
    base_point = baseline.get("operating_point") or {}
    full = (protocol.get("full_split") or {}).get("test") or {}
    reason = "" if chrono is None or chrono.get("meaningful", True) else chrono.get("reason")
    return (
        "HDFS corpus prevalence is "
        f"{_fmt(population.get('prevalence'))}. The preserved benchmark reports "
        f"{_benchmark_prevalence('hdfs')}. Chronological evaluation is not meaningful: {reason} "
        "The group holdout's full test prevalence is "
        f"{_fmt(full.get('prevalence'))} and the evaluated cap is "
        f"{_fmt(forest.get('prevalence'))}, above the corpus rate because whole groups differ in size. "  # noqa: E501
        f"Random forest F1 is {_fmt(forest.get('f1'))} with FP/1,000 {_fmt(forest.get('fp_per_1000_normal'))}; "  # noqa: E501
        f"logistic regression F1 is {_fmt(logistic.get('f1'))} with FP/1,000 "
        f"{_fmt(logistic.get('fp_per_1000_normal'))}. "
        f"After near-duplicate removal, random-forest F1 is {_fmt(dropped.get('f1'))}. "
        f"The single train-chosen event id {baseline.get('token')} has test F1 "
        f"{_fmt(base_point.get('f1'))} and recall {_fmt(base_point.get('recall'))}, "
        "so the text models are not that one token. "
        f"Isolation Forest F1 is {_fmt(isolation.get('f1'))} with FP/1,000 "
        f"{_fmt(isolation.get('fp_per_1000_normal'))}. "
        "There is no future-time holdout for HDFS in this run."
    )


def _openstack_support(experiment: dict[str, Any] | None) -> str:
    protocol = _protocol(experiment, "realistic_group")
    if experiment is None or protocol is None:
        return ""
    population = experiment.get("population") or {}
    forest = _fitted(protocol, "isolation_forest") or {}
    supervised = _fitted(protocol, "random_forest") or {}
    near = protocol.get("near_duplicates") or {}
    test_rows = (protocol.get("evaluated_rows") or {}).get("test") or {}
    return (
        "OpenStack has "
        f"{population.get('anomaly')} anomalous instances and "
        f"{population.get('normal')} normal instances. "
        f"Majority-anomaly templates: {experiment.get('positive_template_groups')}. "
        f"Templates that contain any anomaly: {protocol.get('anomaly_bearing_groups')}, "
        f"placed {protocol.get('anomaly_group_placement')}. "
        f"The evaluated test prevalence is {_fmt(test_rows.get('prevalence'))}. "
        f"Supervised models were refused: {supervised.get('detail')} "
        f"Isolation Forest was fit and then not scored: {forest.get('detail')} "
        f"Median nearest-train Jaccard on the test templates is {_fmt(near.get('median_max_jaccard'))}. "  # noqa: E501
        "Four anomalous instances inside one mixed template do not support a supervised deployment claim."  # noqa: E501
    )


def _hadoop_support(experiment: dict[str, Any] | None) -> str:
    protocol = _protocol(experiment, "realistic_group")
    chrono = _protocol(experiment, "chronological_group")
    if experiment is None or protocol is None or chrono is None:
        return ""
    population = experiment.get("population") or {}
    forest = _op(_fitted(protocol, "random_forest"))
    isolation = _op(_fitted(chrono, "isolation_forest"))
    near = protocol.get("near_duplicates") or {}
    excluded = (_fitted(protocol, "random_forest") or {}).get("near_duplicate_excluded") or {}
    leakage = experiment.get("leakage") or {}
    return (
        "Hadoop has "
        f"{population.get('template_groups')} application templates, "
        f"{population.get('anomaly')} anomalous and {population.get('normal')} normal. "
        f"The random holdout scores {(_fitted(protocol, 'random_forest') or {}).get('n_test')} test applications "  # noqa: E501
        f"at prevalence {_fmt(forest.get('prevalence'))}. "
        f"Random forest F1 is {_fmt(forest.get('f1'))} with FP/1,000 {_fmt(forest.get('fp_per_1000_normal'))} "  # noqa: E501
        f"and ROC-AUC {_fmt(forest.get('roc_auc'))}. "
        f"Median nearest-train Jaccard is {_fmt(near.get('median_max_jaccard'))}. "
        f"Near-duplicate removal leaves n={excluded.get('n_test')}: {excluded.get('note')} "
        f"Raw identifiers left in features: {leakage.get('identifier_in_features')}. "
        "The chronological Isolation Forest result, F1 "
        f"{_fmt(isolation.get('f1'))} on "
        f"{(_fitted(chrono, 'isolation_forest') or {}).get('n_test')} rows, "
        "is one small draw and the same near-duplicate filter empties that test too. "
        "Hadoop does not support deployment."
    )


def _thunderbird_support(experiment: dict[str, Any] | None) -> str:
    if experiment is None:
        return ""
    population = experiment.get("population") or {}
    chrono = _protocol(experiment, "chronological_group") or {}
    reason = chrono.get("reason") if not chrono.get("meaningful", True) else ""
    total = (population.get("anomaly") or 0) + (population.get("normal") or 0)
    return (
        "Thunderbird_2k has "
        f"{population.get('anomaly')} anomalous rows out of {total}. "
        "Accuracy is not computed. "
        + (reason or "A chronological split was not meaningful.")
        + " The full Thunderbird corpus was not evaluated."
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="sentinellog.risk.realistic")
    parser.add_argument("dataset_dir", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    payload = evaluate_directory(args.dataset_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    args.report.write_text(render_report(payload), encoding="utf-8")
    for experiment in payload["experiments"]:
        statuses = []
        for protocol in experiment.get("protocols") or []:
            statuses.append(
                (
                    protocol["name"],
                    [model["metrics_status"] for model in protocol.get("models") or []],
                )
            )
        print(experiment["dataset"], statuses or experiment.get("metrics_note"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
