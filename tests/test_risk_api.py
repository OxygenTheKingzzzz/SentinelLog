"""API coverage for labels, unsupervised bands, and verified-label training."""

from sentinellog.ingestion.service import create_source, import_raw_log
from sentinellog.models import LogEvent, RiskLabel
from sentinellog.risk.constants import NOT_EVALUATED
from sentinellog.risk.service import train_labeled

_RAW = "".join(
    f"Jun 14 15:16:{index:02d} combo sshd(pam_unix)[{index + 1}]: "
    f"{'failed' if index < 8 else 'accepted'} session {letter} host\n"
    for index, letter in enumerate("abcdefghijklmnop")
)


def test_linux_experiments_are_not_a_fabricated_accuracy(client):
    payload = client.get("/api/v1/risk/experiments").json()
    linux = next(item for item in payload["experiments"] if item["dataset"] == "linux")
    assert linux["models"][0]["metrics"] is None
    assert linux["models"][0]["metrics_note"] == NOT_EVALUATED
    assert linux["models"][0]["real_world"] is False


def test_bands_do_not_report_accuracy(client):
    source = client.post("/api/v1/sources", json={"name": "band-source", "source_year": 2005})
    source_id = source.json()["id"]
    raw = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("tiny.log", _RAW, "text/plain")},
    )
    assert raw.status_code == 200, raw.text
    trained = client.post("/api/v1/risk/bands", params={"source_id": source_id})
    assert trained.status_code == 200, trained.text
    body = trained.json()
    assert body["metrics"] is None
    assert body["metrics_note"] == NOT_EVALUATED
    assert body["real_world"] is False
    page = client.get("/api/v1/risk/predictions", params={"source_id": source_id})
    assert page.status_code == 200, page.text
    item = page.json()["items"][0]
    assert item["predicted_risk"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert item["anomaly_score"] is not None
    assert item["class_confidence"] is None
    assert item["score_kind"] == "anomaly_score"
    assert item["verified_label"] is None
    assert "not a class probability" in item["explanation"]["summary"]


def test_verified_training_reports_held_out_metrics(client):
    source = client.post("/api/v1/sources", json={"name": "verified-source", "source_year": 2005})
    source_id = source.json()["id"]
    imported = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("tiny.log", _RAW, "text/plain")},
    )
    assert imported.status_code == 200, imported.text
    events = client.get("/api/v1/events", params={"source_id": source_id, "limit": 50}).json()
    assert events["total"] == 16
    for item in events["items"]:
        level = "HIGH" if "failed" in item["content"] else "LOW"
        saved = client.post(
            "/api/v1/risk/labels",
            json={"log_event_id": item["id"], "risk_level": level, "note": "reviewer"},
        )
        assert saved.status_code == 200, saved.text
        assert saved.json()["provenance"] == "verified_manual"
    trained = client.post(
        "/api/v1/risk/train",
        params={"source_id": source_id, "label_provenance": "verified_manual"},
    )
    assert trained.status_code == 200, trained.text
    models = trained.json()
    supervised = [model for model in models if model["algorithm"] != "isolation_forest"]
    assert supervised
    assert any(
        model["real_world"] is True and model["metrics"]["n_test"] > 0 for model in supervised
    )
    for model in supervised:
        if model["metrics"] is not None:
            assert model["metrics_note"] != NOT_EVALUATED
            assert "n_train" in model["metrics"]
            assert "confusion_matrix" in model["metrics"]
    forest = next(model for model in models if model["algorithm"] == "isolation_forest")
    assert forest["metrics"] is None
    assert forest["metrics_note"] == NOT_EVALUATED


def test_weak_labels_do_not_become_accuracy(db):
    source = create_source(db, name="weak-source", description=None, source_year=2005)
    import_raw_log(db, source_id=source.id, filename="tiny.log", data=_RAW.encode(), actor="test")
    events = db.query(LogEvent).filter(LogEvent.source_id == source.id).all()
    for event in events:
        level = "HIGH" if "failed" in event.content else "LOW"
        db.add(
            RiskLabel(
                log_event_id=event.id,
                risk_level=level,
                provenance="weak_rule",
                reviewer="test",
                note="Weak label copied from rule alert severity. Not verified ground truth.",
            )
        )
    db.commit()
    models = train_labeled(db, source_id=source.id, provenance="weak_rule", actor="test")
    assert models
    for model in models:
        assert model.metrics is None
        assert model.metrics_status == "weak_agreement_only"
        assert model.metrics_note == NOT_EVALUATED
        assert model.config["real_world"] is False
