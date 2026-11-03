"""Anomaly models on the real Linux_2k events. No ground-truth metrics."""

from datetime import datetime, timedelta

from sqlalchemy import func, select
from tests.test_detection import _import_without_year

from sentinellog.config import get_settings
from sentinellog.detection.backfill import assign_source_year, backfill_timestamps
from sentinellog.detection.service import detect
from sentinellog.ml.constants import (
    BASELINE_Z_THRESHOLD,
    ISOLATION_SCORE_THRESHOLD,
    NO_GROUND_TRUTH,
    SCALAR_FEATURES,
)
from sentinellog.models import AnomalyScore, LogEvent, SecurityAlert

FORBIDDEN_KEYS = {"precision", "recall", "f1", "roc_auc", "rocauc", "accuracy"}


def _forbid_metrics(payload: object) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            assert key.lower() not in FORBIDDEN_KEYS
            _forbid_metrics(value)
    elif isinstance(payload, list):
        for value in payload:
            _forbid_metrics(value)


def _signature(items: list[dict]) -> list[tuple]:
    return [
        (
            item["window_start"],
            item["isolation_score"],
            item["baseline_score"],
            item["flagged_isolation"],
            item["flagged_baseline"],
            item["features"],
            item["explanation"],
        )
        for item in items
    ]


def test_linux_2k_scores_are_reproducible_and_separate_from_alerts(
    client, db, tmp_path, monkeypatch
):
    monkeypatch.setattr(get_settings(), "anomaly_artifact_dir", str(tmp_path))
    source = _import_without_year(db, "linux-ml")
    assign_source_year(db, source, 2005, actor="test")
    db.commit()
    filled = backfill_timestamps(db, source_id=source.id, actor="test")
    assert filled.updated == 2000
    detected = detect(db, source_id=source.id, actor="test")
    assert detected.created == 162
    alert_ids = set(db.scalars(select(SecurityAlert.id)).all())
    assert len(alert_ids) == 162

    trained = client.post("/api/v1/ml/train", params={"source_id": str(source.id)})
    assert trained.status_code == 200, trained.text
    model = trained.json()
    _forbid_metrics(model)
    assert model["ground_truth"] is False
    assert model["metrics"] is None
    assert "ROC-AUC are not computed" in model["metrics_note"]
    assert model["metrics_note"] == NO_GROUND_TRUTH
    assert model["dropped_features"] == []
    assert model["n_train"] == 103
    assert model["n_validation"] == 45
    assert model["window_seconds"] == 3600
    assert model["window_type"] == "tumbling"
    assert model["baseline_z_threshold"] == BASELINE_Z_THRESHOLD
    assert model["isolation_score_threshold"] == ISOLATION_SCORE_THRESHOLD
    assert model["version"] == 1
    names = model["feature_names"]
    for feature, _columns in SCALAR_FEATURES:
        assert feature in names
    assert "template_count:E1" in names
    assert "template_count:__other__" in names
    assert "component_count:__other__" in names
    assert all("alert" not in name and "label" not in name for name in names)
    assert model["validation_summary"]["ground_truth"] is False
    assert model["validation_summary"]["metrics"] is None
    assert "precision" not in model["validation_summary"]

    first = client.post("/api/v1/ml/score", params={"source_id": str(source.id)})
    assert first.status_code == 200, first.text
    assert first.json()["windows"] == 148
    assert first.json()["ground_truth"] is False
    assert first.json()["metrics"] is None
    page = client.get(
        "/api/v1/ml/scores",
        params={"source_id": str(source.id), "model_id": model["id"], "limit": 1000},
    )
    assert page.status_code == 200, page.text
    body = page.json()
    _forbid_metrics(body)
    assert body["total"] == 148
    assert body["ground_truth"] is False
    assert len(body["items"]) == 148
    saved = _signature(body["items"])

    again = client.post("/api/v1/ml/score", params={"source_id": str(source.id)})
    assert again.status_code == 200
    page_again = client.get(
        "/api/v1/ml/scores",
        params={"source_id": str(source.id), "model_id": model["id"], "limit": 1000},
    )
    assert _signature(page_again.json()["items"]) == saved

    db.expire_all()
    events = list(db.scalars(select(LogEvent).where(LogEvent.source_id == source.id)).all())
    feature_names = set(names)
    roles = set()
    for item in body["items"]:
        start = datetime.fromisoformat(item["window_start"])
        end = datetime.fromisoformat(item["window_end"])
        assert end - start == timedelta(seconds=3600)
        in_window = [
            event
            for event in events
            if event.event_timestamp is not None and start <= event.event_timestamp < end
        ]
        assert item["features"]["event_count"] == len(in_window) == item["event_count"]
        assert item["features"]["ftp_connection_count"] == sum(
            1 for event in in_window if event.event_id == "E29"
        )
        assert item["features"]["service_error_count"] == sum(
            1
            for event in in_window
            if event.event_id == "E8"
            and event.component == "logrotate"
            and "ALERT exited abnormally" in event.content
        )
        assert item["flagged_isolation"] is (item["isolation_score"] > ISOLATION_SCORE_THRESHOLD)
        assert item["flagged_baseline"] is (item["baseline_score"] >= BASELINE_Z_THRESHOLD)
        assert item["ground_truth"] is False
        assert item["explanation"]["no_ground_truth"] is True
        assert item["explanation"]["metrics"] is None
        contributions = item["explanation"]["isolation_contributions"]
        baseline = item["explanation"]["baseline"]
        assert contributions
        assert baseline
        for cited in contributions + baseline:
            assert cited["feature"] in feature_names
            assert cited["value"] == item["features"][cited["feature"]]
        roles.add(item["split_role"])
    assert roles == {"train", "validation"}
    assert sum(1 for item in body["items"] if item["split_role"] == "train") == 103

    retrained = client.post("/api/v1/ml/train", params={"source_id": str(source.id)})
    assert retrained.status_code == 200, retrained.text
    second_model = retrained.json()
    assert second_model["version"] == 2
    rescored = client.post(
        "/api/v1/ml/score",
        params={"source_id": str(source.id), "model_id": second_model["id"]},
    )
    assert rescored.status_code == 200
    second_page = client.get(
        "/api/v1/ml/scores",
        params={"source_id": str(source.id), "model_id": second_model["id"], "limit": 1000},
    )
    assert _signature(second_page.json()["items"]) == saved

    db.expire_all()
    assert set(db.scalars(select(SecurityAlert.id)).all()) == alert_ids
    assert db.scalar(select(func.count()).select_from(SecurityAlert)) == 162
    assert db.scalar(select(func.count()).select_from(AnomalyScore)) == 296
