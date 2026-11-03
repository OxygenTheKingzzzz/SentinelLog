"""Invariants for the generated realistic-prevalence file. Numbers come from the run."""

import hashlib
import json
from pathlib import Path

from sentinellog.risk.constants import NOT_EVALUATED

PUBLISHED = Path("src/sentinellog/risk/published_results.json")
REALISTIC = Path("src/sentinellog/risk/realistic_results.json")
PUBLISHED_SHA256 = "17f3e49b5017decf02fc6ac7494fc76cb4758160fe214dd09cc3248bf99d5ca2"
SEVERITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
REFUSAL = "Fewer than two template groups contain any anomaly."


def _load() -> dict:
    return json.loads(REALISTIC.read_text(encoding="utf-8"))


def test_published_benchmark_hash_is_unchanged():
    digest = hashlib.sha256(PUBLISHED.read_bytes()).hexdigest()
    assert digest == PUBLISHED_SHA256


def test_linux_stays_unevaluated_and_binary_labels_are_not_severity():
    payload = _load()
    linux = next(item for item in payload["experiments"] if item["dataset"] == "linux")
    assert linux["metrics_note"] == NOT_EVALUATED
    assert linux["protocols"] == []
    assert linux["real_world"] is False
    for experiment in payload["experiments"]:
        for protocol in experiment.get("protocols") or []:
            for model in protocol.get("models") or []:
                point = model.get("operating_point") or {}
                matrix = (point.get("confusion_matrix") or {}) if point else {}
                labels = matrix.get("labels") or []
                assert SEVERITY.isdisjoint(labels)
                if model.get("metrics_status") != "evaluated":
                    assert model["real_world"] is False
                    assert model["metrics_note"] == NOT_EVALUATED
                    continue
                assert model["real_world"] is True
                assert 0.0 <= point["accuracy"] <= 1.0
                assert point["fp_per_1000_normal"] is not None
                total = sum(sum(row) for row in matrix["matrix"])
                assert total == model["n_test"]
                source = (model.get("threshold") or {}).get("source")
                assert source in {
                    "validation_max_anomaly_f1",
                    "default_because_validation_has_one_class",
                }


def test_bgl_realistic_prevalence_is_not_the_rebalanced_benchmark():
    payload = _load()
    bgl = next(item for item in payload["experiments"] if item["dataset"] == "bgl")
    realistic = next(item for item in bgl["protocols"] if item["name"] == "realistic_group")
    prevalence = realistic["evaluated_rows"]["test"]["prevalence"]
    assert prevalence < 0.2
    forest = next(item for item in realistic["models"] if item["algorithm"] == "random_forest")
    assert forest["real_world"] is True


def test_openstack_supervised_models_are_refused_for_one_anomaly_template():
    payload = _load()
    openstack = next(item for item in payload["experiments"] if item["dataset"] == "openstack")
    assert "do not contain both classes" not in json.dumps(openstack)
    protocols = [item for item in openstack["protocols"] if item.get("meaningful", True)]
    assert protocols
    for protocol in protocols:
        assert protocol["anomaly_bearing_groups"] < 2
        by_name = {model["algorithm"]: model for model in protocol["models"]}
        for algorithm in ("random_forest", "tfidf_logreg"):
            assert by_name[algorithm]["real_world"] is False
            assert REFUSAL in (by_name[algorithm].get("detail") or "")
        forest = by_name["isolation_forest"]
        assert REFUSAL not in (forest.get("detail") or "")
