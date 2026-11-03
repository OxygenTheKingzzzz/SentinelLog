"""Investigation JSON and PDF over real Linux_2k alerts. No new model or rule."""

from sqlalchemy import select
from tests.test_detection import _import_without_year

from sentinellog.config import get_settings
from sentinellog.detection.backfill import assign_source_year, backfill_timestamps
from sentinellog.detection.service import detect
from sentinellog.investigations.report import NOT_CONFIRMED, SECTIONS
from sentinellog.models import SecurityAlert


def test_linux_2k_investigation_exports_json_and_pdf(client, db, tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "anomaly_artifact_dir", str(tmp_path))
    source = _import_without_year(db, "linux-report")
    assign_source_year(db, source, 2005, actor="test")
    db.commit()
    filled = backfill_timestamps(db, source_id=source.id, actor="test")
    assert filled.updated == 2000
    detected = detect(db, source_id=source.id, actor="test")
    assert detected.created == 162

    trained = client.post("/api/v1/ml/train", params={"source_id": str(source.id)})
    assert trained.status_code == 200, trained.text
    scored = client.post("/api/v1/ml/score", params={"source_id": str(source.id)})
    assert scored.status_code == 200, scored.text
    assert scored.json()["windows"] == 148

    alerts = list(db.scalars(select(SecurityAlert).order_by(SecurityAlert.id).limit(2)).all())
    assert len(alerts) == 2
    created = client.post(
        "/api/v1/investigations",
        json={
            "title": "linux-2k sample",
            "summary": "Selected stored alerts only.",
            "alert_ids": [str(alert.id) for alert in alerts],
            "note": "Analyst opened this from the stored alerts.",
            "actor": "analyst",
        },
    )
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]

    noted = client.post(
        f"/api/v1/investigations/{investigation_id}/notes",
        json={"body": "Compared the lines with the rule window.", "actor": "analyst"},
    )
    assert noted.status_code == 201, noted.text
    closed = client.patch(
        f"/api/v1/investigations/{investigation_id}/status",
        json={
            "status": "closed",
            "note": "No further stored lines to attach.",
            "actor": "analyst",
        },
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "closed"

    evidence = client.get(
        f"/api/v1/investigations/{investigation_id}/evidence",
        params={"actor": "analyst"},
    )
    assert evidence.status_code == 200, evidence.text
    report = evidence.json()
    assert report["kind"] == "investigation_report"
    assert [report[name]["section"] for name in SECTIONS] == list(SECTIONS)
    assert "was compromised" not in evidence.text

    timeline = report["observations"]["timeline"]
    assert timeline
    assert [item["event_timestamp"] for item in timeline] == sorted(
        item["event_timestamp"] for item in timeline
    )
    assert all(item["raw_line"] and item["event_timestamp"] for item in timeline)

    rule_alerts = report["automated_hypotheses"]["rule_alerts"]
    assert {item["id"] for item in rule_alerts} == {str(alert.id) for alert in alerts}
    for item in rule_alerts:
        assert item["rule_id"]
        assert item["rule_version"] >= 1
        assert item["threshold"] >= 1
        assert item["confirmed_compromise"] is False
        assert item["label"] == NOT_CONFIRMED
    windows = report["automated_hypotheses"]["anomaly_windows"]
    assert windows
    for item in windows:
        assert item["confirmed_compromise"] is False
        assert item["label"] == NOT_CONFIRMED
        assert item["window_start"] and item["window_end"]

    findings = report["analyst_confirmed_findings"]
    assert set(findings) == {"section", "label", "description", "notes"}
    bodies = [note["body"] for note in findings["notes"]]
    assert bodies == [
        "Analyst opened this from the stored alerts.",
        "Compared the lines with the rule window.",
        "No further stored lines to attach.",
    ]

    pdf = client.get(
        f"/api/v1/investigations/{investigation_id}/report.pdf",
        params={"actor": "analyst"},
    )
    assert pdf.status_code == 200, pdf.text
    assert pdf.headers["content-type"].startswith("application/pdf")
    assert pdf.content.startswith(b"%PDF")
    assert b"Observations" in pdf.content
    assert b"Automated hypotheses" in pdf.content
    assert b"Analyst-confirmed findings" in pdf.content
    assert b"not a confirmed compromise" in pdf.content
    assert b"was compromised" not in pdf.content
    assert str(alerts[0].rule_id).encode() in pdf.content
    assert f"threshold {alerts[0].threshold}".encode() in pdf.content

    audit = client.get("/api/v1/audit", params={"limit": 200})
    assert audit.status_code == 200
    rows = [item for item in audit.json()["items"] if item["entity_id"] == investigation_id]
    assert any(
        item["action"] == "investigation.status" and item["details"]["to_status"] == "closed"
        for item in rows
    )
    formats = {
        item["details"]["format"] for item in rows if item["action"] == "investigation.export"
    }
    assert formats == {"json", "pdf"}
    for item in rows:
        if item["action"] == "investigation.export":
            assert item["details"]["sections"] == list(SECTIONS)
            assert "raw_line" not in item["details"]
