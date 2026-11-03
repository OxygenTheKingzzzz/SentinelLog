"""The realistic split is assigned before sampling, and thresholds see validation only."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from sentinellog.risk.constants import NOT_EVALUATED
from sentinellog.risk.prevalence import (
    Catalog,
    assign_splits,
    false_positives_per_thousand,
    near_duplicate_report,
    select_f1_threshold,
    uniform_cap,
)
from sentinellog.risk.realistic import _assignments, _evaluate_protocol, _package
from sentinellog.risk.records import Example
from sentinellog.risk.textnorm import group_key, normalize_template

PUBLISHED_SHA256 = "17f3e49b5017decf02fc6ac7494fc76cb4758160fe214dd09cc3248bf99d5ca2"


def _catalog(rows: list[tuple[str, str, datetime]]) -> tuple[Catalog, list[Example]]:
    catalog = Catalog()
    examples: list[Example] = []
    for text, label, moment in rows:
        example = Example(
            key=text,
            content=text,
            group_key=group_key(text),
            timestamp=moment,
            component="kernel",
            pid=None,
            severity_rank=3 if label == "anomaly" else 0,
            label=label,
        )
        catalog.observe(
            key=example.group_key,
            signature=normalize_template(text),
            label=label,
            timestamp=moment,
            severity=example.severity_rank,
        )
        examples.append(example)
    return catalog, examples


def test_published_benchmark_file_is_unchanged():
    digest = hashlib.sha256(
        Path("src/sentinellog/risk/published_results.json").read_bytes()
    ).hexdigest()
    assert digest == PUBLISHED_SHA256


def test_groups_are_assigned_before_any_row_is_dropped():
    names = "abcdefghijkl"
    rows = []
    moment = datetime(2005, 6, 1, tzinfo=UTC)
    for index in range(12):
        for _copy in range(6):
            label = "anomaly" if index < 3 else "normal"
            text = f"disk event family {names[index]} code ten"
            rows.append((text, label, moment.replace(day=1 + index)))
    catalog, examples = _catalog(rows)
    full = sum(stat.size for stat in catalog.groups.values())
    assert full == len(examples)
    assignment = assign_splits(catalog, mode="stratified", seed=42)
    roles = assignment["roles"]
    assert set(roles) == set(catalog.groups)
    assert set(roles.values()) == {"train", "validation", "test"}
    sides = {
        role: [item for item in examples if roles[item.group_key] == role]
        for role in ("train", "validation", "test")
    }
    assert {item.group_key for item in sides["train"]}.isdisjoint(
        {item.group_key for item in sides["test"]}
    )
    capped = uniform_cap(sides["test"], 3, 7)
    assert {item.group_key for item in capped} <= {item.group_key for item in sides["test"]}
    population = assignment["counts"]["population"]["prevalence"]
    tested = assignment["counts"]["test"]["prevalence"]
    assert tested < 0.6
    assert population < 0.5


def test_chronological_holdout_is_the_latest_templates():
    names = "abcdefghi"
    rows = []
    for index in range(9):
        label = "anomaly" if index % 3 == 0 else "normal"
        moment = datetime(2005, 6, index + 1, tzinfo=UTC)
        rows.append((f"service family {names[index]}", label, moment))
    catalog, _examples = _catalog(rows)
    assignment = assign_splits(catalog, mode="chronological", seed=1)
    roles = assignment["roles"]
    train_end = max(catalog.groups[key].earliest for key, role in roles.items() if role == "train")
    test_start = min(catalog.groups[key].earliest for key, role in roles.items() if role == "test")
    assert train_end is not None and test_start is not None
    assert train_end < test_start
    assert assignment["span_overlap"]["train_groups_extending_into_test"] == 0


def test_threshold_is_chosen_from_validation_scores_only():
    labels = ["normal", "anomaly"]
    scores = np.asarray([0.1, 0.9])
    chosen = select_f1_threshold(labels, scores)
    assert chosen["source"] == "validation_max_anomaly_f1"
    assert chosen["value"] is not None
    assert 0.1 < chosen["value"] <= 0.9


def test_false_positives_per_thousand_uses_the_normal_row():
    value = false_positives_per_thousand([[990, 10], [1, 2]], ["normal", "anomaly"])
    assert value == 10


def test_near_duplicate_templates_are_reported_without_sharing_a_group():
    report = near_duplicate_report(
        [("train-a", "kernel fatal disk sector offline")],
        [("test-b", "kernel fatal disk sector offline now"), ("test-c", "cron job finished")],
    )
    assert report["exact_group_overlap"] == 0
    assert report["jaccard_at_least_0_8"] == 1
    assert report["near_keys"] == ["test-b"]


def test_tiny_natural_split_scores_binary_metrics_only():
    names = "abcdefghijklmnop"
    rows = []
    for index in range(16):
        for _copy in range(4):
            label = "anomaly" if index < 4 else "normal"
            moment = datetime(2005, 7, 1 + index, tzinfo=UTC)
            kind = "fatal" if label == "anomaly" else "info"
            text = f"component {kind} family {names[index]}"
            rows.append((text, label, moment))
    catalog, examples = _catalog(rows)
    assignment = assign_splits(catalog, mode="stratified", seed=42)
    roles = assignment["roles"]
    sampled = {
        role: [item for item in examples if roles[item.group_key] == role]
        for role in ("train", "validation", "test")
    }
    protocol = _evaluate_protocol(
        "realistic_group",
        assignment,
        sampled,
        catalog,
        single_positive=False,
        event_baseline=False,
        severity_baseline=True,
    )
    evaluated = [model for model in protocol["models"] if model["real_world"]]
    assert evaluated
    for model in evaluated:
        assert model["operating_point"]["fp_per_1000_normal"] is not None
        assert "LOW" not in str(model["operating_point"]["confusion_matrix"]["labels"])
        assert model["threshold"]["source"] == "validation_max_anomaly_f1"
    refused = [model for model in protocol["models"] if not model["real_world"]]
    for model in refused:
        assert model["metrics_note"] == NOT_EVALUATED


def test_one_mixed_template_does_not_erase_the_normal_class():
    """OpenStack's anomalies share one template with normal rows.

    Majority-anomaly groups are zero, but both row labels exist. Supervised
    models stay refused. Isolation Forest is still fit.
    """
    moment = datetime(2017, 1, 1, tzinfo=UTC)
    rows: list[tuple[str, str, datetime]] = []
    for _copy in range(3):
        rows.append(("vm spawn image ready", "anomaly", moment))
    for _copy in range(12):
        rows.append(("vm spawn image ready", "normal", moment.replace(day=2)))
    for index, name in enumerate("abcdef"):
        for _copy in range(4):
            rows.append(
                (f"vm health family {name}", "normal", moment.replace(day=3 + index))
            )
    catalog, examples = _catalog(rows)
    assignments = _assignments(catalog)
    sampled: dict = {}
    for name, assignment in assignments.items():
        if assignment is None:
            continue
        roles = assignment["roles"]
        sampled[name] = {
            role: [item for item in examples if roles[item.group_key] == role]
            for role in ("train", "validation", "test")
        }
    result = _package({"dataset": "openstack"}, catalog, assignments, sampled)
    assert result["positive_template_groups"] == 0
    assert result["mixed_label_groups"] == 1
    meaningful = [item for item in result["protocols"] if item.get("meaningful", True)]
    assert meaningful
    for protocol in meaningful:
        details = " ".join(model.get("detail") or "" for model in protocol["models"])
        assert "do not contain both classes" not in details
        assert protocol["anomaly_bearing_groups"] == 1
        by_name = {model["algorithm"]: model for model in protocol["models"]}
        assert by_name["random_forest"]["real_world"] is False
        assert by_name["tfidf_logreg"]["real_world"] is False
        assert "Fewer than two template groups" in by_name["random_forest"]["detail"]
        forest = by_name["isolation_forest"]
        assert "Fewer than two template groups" not in (forest.get("detail") or "")
        assert "do not contain both classes" not in (forest.get("detail") or "")
        if forest["real_world"]:
            labels = forest["operating_point"]["confusion_matrix"]["labels"]
            assert labels == ["normal", "anomaly"]
        else:
            assert forest["metrics_note"] == NOT_EVALUATED
