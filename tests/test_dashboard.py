"""Dashboard aggregates and investigation workspace. Counts come from the database."""

TINY = (
    b"Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; "
    b"logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 \n"
    b"Jun 15 04:06:18 combo su(pam_unix)[21416]: session opened for user cyrus by (uid=0)\n"
)


def test_overview_facets_and_settings_follow_stored_rows(client):
    from tests.test_ingest import TEMPLATES

    source = client.post(
        "/api/v1/sources",
        json={"name": "dash-sample", "source_year": 2005},
    )
    assert source.status_code == 201, source.text
    source_id = source.json()["id"]
    templates = client.post(
        f"/api/v1/sources/{source_id}/ingest/templates",
        files={"file": ("Linux_2k.log_templates.csv", TEMPLATES, "text/csv")},
    )
    assert templates.status_code == 200, templates.text
    raw = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("tiny.log", TINY, "text/plain")},
    )
    assert raw.status_code == 200, raw.text
    assert raw.json()["lines_parsed"] == 2

    missing = client.get(
        "/api/v1/overview",
        params={"source_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert missing.status_code == 404

    overview = client.get("/api/v1/overview", params={"source_id": source_id})
    assert overview.status_code == 200, overview.text
    body = overview.json()
    listed = client.get("/api/v1/events", params={"source_id": source_id, "limit": 1})
    assert body["events"] == listed.json()["total"] == 2
    assert sum(day["events"] for day in body["daily"]) == body["events"]
    assert body["auth_failures"] == 1
    assert sum(day["auth_failures"] for day in body["daily"]) == body["auth_failures"]
    alerts = client.get("/api/v1/alerts", params={"source_id": source_id, "limit": 1})
    assert alerts.status_code == 200
    assert body["alerts"] == alerts.json()["total"]
    assert sum(row["count"] for row in body["severity"]) == body["alerts"]
    assert body["investigations"] == 0
    assert body["ingestion"]["jobs_completed"] >= 1
    assert body["ingestion"]["parse_errors"] == 0
    assert body["sources"][0]["events"] == 2
    assert body["sources"][0]["id"] == source_id

    facets = client.get("/api/v1/events/facets", params={"source_id": source_id})
    assert facets.status_code == 200, facets.text
    assert facets.json()["total"] == 2
    components = {row["value"] for row in facets.json()["components"]}
    assert "sshd(pam_unix)" in components
    line = client.get(
        "/api/v1/events",
        params={"source_id": source_id, "line_number": 1, "limit": 5},
    )
    assert line.json()["total"] == 1
    assert line.json()["items"][0]["line_number"] == 1

    bad_sort = client.get("/api/v1/alerts", params={"sort": "nope"})
    assert bad_sort.status_code == 400

    settings = client.get("/api/v1/settings")
    assert settings.status_code == 200, settings.text
    payload = settings.json()
    assert payload["version"] == "0.8.0"
    assert payload["pdf_export"] is True
    assert payload["live_collection"] is True
    assert "password" not in payload["database"]
    assert "sentinellog" not in str(payload["database"].get("password", ""))
    assert payload["database"]["name"]
    assert "postgresql+psycopg://" not in settings.text

    audit = client.get("/api/v1/audit")
    assert audit.status_code == 200
    assert audit.json()["total"] >= 1


def test_investigation_evidence_uses_real_links(client):
    source = client.post("/api/v1/sources", json={"name": "dash-case", "source_year": 2005})
    source_id = source.json()["id"]
    raw = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("tiny.log", TINY, "text/plain")},
    )
    assert raw.status_code == 200, raw.text
    event = client.get("/api/v1/events", params={"source_id": source_id, "limit": 1})
    event_id = event.json()["items"][0]["id"]
    line_number = event.json()["items"][0]["line_number"]

    created = client.post(
        "/api/v1/investigations",
        json={
            "title": "follow the first line",
            "event_ids": [event_id],
            "note": "opened while checking the workspace",
        },
    )
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]
    assert created.json()["events"][0]["id"] == event_id
    assert created.json()["notes"][0]["body"] == "opened while checking the workspace"

    evidence = client.get(f"/api/v1/investigations/{investigation_id}/evidence")
    assert evidence.status_code == 200, evidence.text
    bundle = evidence.json()
    assert bundle["pdf"] is True
    assert bundle["kind"] == "investigation_report"
    assert bundle["observations"]["section"] == "observations"
    assert bundle["observations"]["timeline"][0]["line_number"] == line_number
    assert bundle["observations"]["timeline"][0]["raw_line"]
    assert bundle["automated_hypotheses"]["section"] == "automated_hypotheses"
    assert bundle["automated_hypotheses"]["rule_alerts"] == []
    assert bundle["automated_hypotheses"]["anomaly_windows"] == []
    findings = bundle["analyst_confirmed_findings"]
    assert findings["section"] == "analyst_confirmed_findings"
    assert findings["notes"][0]["body"] == "opened while checking the workspace"
    assert "was compromised" not in evidence.text

    graph = client.get(f"/api/v1/investigations/{investigation_id}/graph")
    assert graph.status_code == 200, graph.text
    node_ids = {node["id"] for node in graph.json()["nodes"]}
    assert f"event:{event_id}" in node_ids
    assert graph.json()["linked_events"] == 1

    closed = client.patch(
        f"/api/v1/investigations/{investigation_id}/status",
        json={"status": "closed", "note": "nothing further to attach"},
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "closed"

    overview = client.get("/api/v1/overview", params={"source_id": source_id})
    assert overview.json()["investigations"] == 1
    assert overview.json()["events"] == 2
