"""Invariants for the committed held-out evaluation file.

The numbers come from `python -m sentinellog.risk.experiments`. This test checks
that the file still tells the truth about unevaluated datasets and that every
reported confusion matrix matches its split counts.
"""

import json
import re
from pathlib import Path

from sentinellog.risk.constants import NOT_EVALUATED

RESULTS = Path("src/sentinellog/risk/published_results.json")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _load() -> dict:
    payload = json.loads(RESULTS.read_text(encoding="utf-8"))
    assert payload["generator"] == "sentinellog.risk.experiments"
    assert payload["seed"] == 42
    return payload


def _by_name(payload: dict) -> dict[str, dict]:
    return {item["dataset"]: item for item in payload["experiments"]}


def test_published_file_keeps_unevaluated_datasets_honest():
    experiments = _by_name(_load())
    linux = experiments["linux"]
    assert linux["label_provenance"] == "none"
    assert linux["population"]["verified_risk_labels"] == 0
    assert len(linux["models"]) == 1
    model = linux["models"][0]
    assert model["metrics"] is None
    assert model["metrics_note"] == NOT_EVALUATED
    assert model["real_world"] is False
    assert "accuracy" not in json.dumps(model["metrics"])

    thunderbird = experiments["thunderbird"]
    assert thunderbird["population"]["anomaly"] == 0
    assert thunderbird["population"]["normal"] == 2000
    for model in thunderbird["models"]:
        assert model["metrics_status"] == "not_evaluated"
        assert model["metrics"] is None
        assert model["metrics_note"] == NOT_EVALUATED
        assert model["real_world"] is False

    openstack = experiments["openstack"]
    by_algorithm = {model["algorithm"]: model for model in openstack["models"]}
    for algorithm in ("random_forest", "tfidf_logreg"):
        refused = by_algorithm[algorithm]
        assert refused["metrics_status"] == "not_evaluated"
        assert refused["metrics"] is None
        assert refused["metrics_note"] == NOT_EVALUATED
        assert refused["real_world"] is False
    forest = by_algorithm["isolation_forest"]
    assert forest["fit_protocol"] == "positive_groups_held_out"
    assert forest["metrics"]["n_train_positive"] == 0
    assert forest["metrics"]["n_test_positive"] == 4


def test_published_metrics_match_their_confusion_matrices():
    payload = _load()
    for experiment in payload["experiments"]:
        digest = experiment.get("file_sha256")
        if digest is not None:
            assert HEX64.match(digest)
        for model in experiment["models"]:
            if model["metrics_status"] != "evaluated":
                assert model["real_world"] is False
                assert model["metrics"] is None
                assert model["metrics_note"] == NOT_EVALUATED
                continue
            metrics = model["metrics"]
            assert model["real_world"] is True
            assert model["metrics_note"] is None
            assert model["n_train"] > 0
            assert model["n_test"] > 0
            assert 0.0 <= metrics["accuracy"] <= 1.0
            matrix = metrics["confusion_matrix"]["matrix"]
            assert sum(sum(row) for row in matrix) == model["n_test"]
            assert sum(row["support"] for row in metrics["per_class"]) == model["n_test"]
            assert metrics["n_test_positive"] == next(
                row["support"] for row in metrics["per_class"] if row["label"] == "anomaly"
            )
