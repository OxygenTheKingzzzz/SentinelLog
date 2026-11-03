"""Leakage, metrics, and dataset-parser checks. No fabricated accuracy."""

from datetime import UTC, datetime

from sentinellog.risk.compare import compare_models
from sentinellog.risk.constants import NOT_EVALUATED
from sentinellog.risk.datasets import parse_hadoop_labels, parse_ras_line
from sentinellog.risk.experiments import run_labeled
from sentinellog.risk.metrics import classification_metrics
from sentinellog.risk.records import Example
from sentinellog.risk.textnorm import group_key


def _example(key: str, content: str, label: str) -> Example:
    return Example(
        key=key,
        content=content,
        group_key=group_key(content),
        timestamp=datetime(2020, 1, 1, 12, 0, tzinfo=UTC),
        component="sshd",
        pid=42,
        severity_rank=2 if label == "anomaly" else 0,
        label=label,
    )


def _corpus() -> list[Example]:
    examples: list[Example] = []
    for index, letter in enumerate("abcdefghijklmnop"):
        label = "anomaly" if index < 6 else "normal"
        word = "failed" if label == "anomaly" else "accepted"
        content = f"sshd {word} session {letter} host"
        for copy in range(3):
            examples.append(_example(f"{letter}-{copy}", content, label))
    return examples


def test_group_split_blocks_template_leakage_and_reports_held_out_metrics():
    examples = _corpus()
    runs = compare_models(examples, task="binary_anomaly", seed=42)
    by_name = {run.algorithm: run for run in runs}
    assert set(by_name) == {"isolation_forest", "random_forest", "tfidf_logreg"}
    for run in runs:
        assert run.metrics_status == "evaluated"
        assert run.metrics is not None
        assert run.metrics_note is None
        assert 0.0 <= run.metrics["accuracy"] <= 1.0
        assert run.metrics["roc_auc"] is not None
        assert run.n_train > 0 and run.n_test > 0
        train_groups = {item.example.group_key for item in run.predictions}
        # Predictions are the test side only.
        assert train_groups.isdisjoint(set(run.bundle["train_groups"]))
        assert run.cv["note"] != run.metrics["accuracy"]
        assert "not the held-out test score" in run.cv["note"] or run.cv["folds"] == 0
    encoder = by_name["tfidf_logreg"].bundle["encoder"]
    test_only = set()
    train_text = " ".join(
        item.content
        for item in examples
        if item.group_key in set(by_name["tfidf_logreg"].bundle["train_groups"])
    )
    for item in examples:
        if item.group_key not in set(by_name["tfidf_logreg"].bundle["train_groups"]):
            for token in item.content.split():
                if token not in train_text.split():
                    test_only.add(token)
    assert test_only
    assert test_only.isdisjoint(encoder.vocabulary())


def test_one_class_is_not_evaluated():
    examples = [
        _example(str(index), f"sshd accepted session {letter}", "normal")
        for index, letter in enumerate("abcdef")
    ]
    meta = {
        "dataset": "fixture",
        "dataset_version": "v",
        "source_url": None,
        "file_sha256": None,
        "label_unit": "line",
        "label_provenance": "dataset_native",
        "label_definition": "fixture",
        "population": {"lines": len(examples)},
        "sample": {},
    }
    experiment = run_labeled(examples, meta)
    assert all(model["metrics"] is None for model in experiment["models"])
    assert all(model["metrics_note"] == NOT_EVALUATED for model in experiment["models"])
    assert all(model["real_world"] is False for model in experiment["models"])


def test_single_positive_template_does_not_train_supervised_on_itself():
    examples = []
    for index, letter in enumerate("abcdef"):
        examples.append(_example(f"n{index}", f"sshd accepted session {letter}", "normal"))
    for copy in range(4):
        examples.append(_example(f"a{copy}", "sshd failed session samepattern host", "anomaly"))
    runs = {run.algorithm: run for run in compare_models(examples, task="binary_anomaly", seed=7)}
    assert runs["random_forest"].metrics is None
    assert runs["tfidf_logreg"].metrics is None
    assert runs["random_forest"].metrics_note == NOT_EVALUATED
    assert runs["isolation_forest"].metrics_status == "evaluated"
    assert runs["isolation_forest"].fit_protocol == "positive_groups_held_out"


def test_binary_metrics_match_a_known_matrix():
    result = classification_metrics(
        ["normal", "normal", "anomaly", "anomaly"],
        ["normal", "anomaly", "anomaly", "normal"],
        labels=["normal", "anomaly"],
        scores=[0.1, 0.8, 0.9, 0.2],
    )
    metrics = result["metrics"]
    assert metrics["accuracy"] == 0.5
    assert metrics["confusion_matrix"]["matrix"] == [[1, 1], [1, 1]]
    assert metrics["per_class"][1]["support"] == 2
    assert metrics["roc_auc"] is not None
    assert metrics["pr_auc"] is not None


def test_roc_auc_is_omitted_when_a_class_is_missing():
    result = classification_metrics(
        ["normal", "normal"],
        ["normal", "anomaly"],
        labels=["normal", "anomaly"],
        scores=[0.2, 0.9],
    )
    assert result["metrics"] is None
    assert result["metrics_note"] == NOT_EVALUATED


def test_ras_parser_drops_the_alert_token():
    normal = (
        "- 1117838570 2005.06.03 R02-M1-N0-C:J12-U11 2005-06-03-15.42.50.675872 "
        "R02-M1-N0-C:J12-U11 RAS KERNEL INFO instruction cache parity error corrected"
    )
    alert = (
        "KERNDTLB 1118536327 2005.06.11 R30-M0-N9-C:J16-U01 2005-06-11-17.32.07.581048 "
        "R30-M0-N9-C:J16-U01 RAS KERNEL FATAL data TLB error interrupt"
    )
    parsed_normal = parse_ras_line(normal, 1, "bgl")
    parsed_alert = parse_ras_line(alert, 2, "bgl")
    assert parsed_normal is not None and parsed_normal.label == "normal"
    assert parsed_alert is not None and parsed_alert.label == "anomaly"
    assert "KERNDTLB" not in parsed_alert.content
    assert parsed_alert.severity_rank == 3
    assert parsed_alert.timestamp is not None
    assert parsed_alert.timestamp.hour == 17


def test_hadoop_label_file_is_binary():
    text = """
### WordCount
Normal:
+ application_1
Machine down:
+ application_2
"""
    assert parse_hadoop_labels(text) == {"application_1": "normal", "application_2": "anomaly"}
