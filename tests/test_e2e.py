"""One API path: upload a fixture, parse it, detect, investigate, export JSON."""

TEMPLATE = b"EventId,EventTemplate\nE27,check pass; user unknown\n"
RAW = b"Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown\n"


def test_upload_detect_investigate_and_export_json(client):
    source = client.post(
        "/api/v1/sources",
        json={"name": "e2e-fixture", "source_year": 2005},
    )
    assert source.status_code == 201, source.text
    source_id = source.json()["id"]

    templates = client.post(
        f"/api/v1/sources/{source_id}/ingest/templates",
        files={"file": ("fixture_templates.csv", TEMPLATE, "text/csv")},
    )
    assert templates.status_code == 200, templates.text
    raw = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("fixture.log", RAW, "text/plain")},
    )
    assert raw.status_code == 200, raw.text
    assert raw.json()["lines_parsed"] == 1
    assert raw.json()["lines_errored"] == 0

    events = client.get("/api/v1/events", params={"source_id": source_id, "limit": 10})
    assert events.status_code == 200, events.text
    item = events.json()["items"][0]
    assert item["event_id"] == "E27"
    assert "user unknown" in item["raw_line"]
    assert item["event_timestamp"]

    detected = client.post("/api/v1/detection/run", params={"source_id": source_id})
    assert detected.status_code == 200, detected.text
    assert detected.json()["created"] >= 1

    alerts = client.get("/api/v1/alerts", params={"source_id": source_id, "limit": 10})
    assert alerts.status_code == 200, alerts.text
    alert_id = alerts.json()["items"][0]["id"]

    created = client.post(
        "/api/v1/investigations",
        json={
            "title": "e2e fixture",
            "alert_ids": [alert_id],
            "note": "Reviewed the stored line.",
            "actor": "analyst",
        },
    )
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]

    evidence = client.get(f"/api/v1/investigations/{investigation_id}/evidence")
    assert evidence.status_code == 200, evidence.text
    report = evidence.json()
    assert report["observations"]["section"] == "observations"
    assert report["observations"]["timeline"][0]["raw_line"].startswith("Jun 14")
    assert report["automated_hypotheses"]["section"] == "automated_hypotheses"
    assert report["automated_hypotheses"]["rule_alerts"][0]["id"] == alert_id
    assert report["automated_hypotheses"]["rule_alerts"][0]["confirmed_compromise"] is False
    assert report["analyst_confirmed_findings"]["section"] == "analyst_confirmed_findings"
    assert report["analyst_confirmed_findings"]["notes"][0]["body"] == "Reviewed the stored line."
    assert "was compromised" not in evidence.text
