from tests.test_ingest import RAW, STRUCTURED, TEMPLATES

from sentinellog.config import get_settings


def _source(client, name: str = "api-linux") -> str:
    response = client.post("/api/v1/sources", json={"name": name, "source_year": None})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["source_year"] is None
    assert "severity" not in body
    return body["id"]


def test_api_ingests_real_files_and_dedups(client):
    source_id = _source(client)
    templates = client.post(
        f"/api/v1/sources/{source_id}/ingest/templates",
        files={"file": ("Linux_2k.log_templates.csv", TEMPLATES, "text/csv")},
    )
    assert templates.status_code == 200, templates.text
    assert templates.json()["lines_parsed"] == 118
    assert templates.json()["lines_errored"] == 0

    raw = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("Linux_2k.log", RAW, "text/plain")},
    )
    assert raw.status_code == 200, raw.text
    body = raw.json()
    assert body["lines_total"] == 2000
    assert body["lines_parsed"] == 2000
    assert body["lines_errored"] == 0
    assert body["lines_parsed"] + body["lines_errored"] == body["lines_total"]

    again = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("Linux_2k.log", RAW, "text/plain")},
    )
    assert again.status_code == 200, again.text
    assert again.json()["duplicates_skipped"] == 2000
    assert again.json()["lines_parsed"] == 0

    checked = client.post(
        f"/api/v1/sources/{source_id}/ingest/structured",
        params={"mode": "validate"},
        files={"file": ("Linux_2k.log_structured.csv", STRUCTURED, "text/csv")},
    )
    assert checked.status_code == 200, checked.text
    assert checked.json()["lines_parsed"] == 2000
    assert checked.json()["lines_errored"] == 0

    events = client.get(
        "/api/v1/events",
        params={"source_id": source_id, "component": "ftpd", "limit": 1},
    )
    assert events.status_code == 200
    assert events.json()["total"] == 916
    first = client.get("/api/v1/events", params={"source_id": source_id, "limit": 1})
    item = first.json()["items"][0]
    assert item["hostname"] == "combo"
    assert item["line_number"] == 1
    assert item["pid"] == 19939
    assert "severity" not in item
    assert item["raw_line"].endswith(" ")

    quality = client.get(f"/api/v1/sources/{source_id}/quality")
    assert quality.status_code == 200
    report = quality.json()
    assert report["events"] == 2000
    assert report["parse_errors"] == 0
    assert report["events_missing_pid"] == 151

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    detection = client.get("/api/v1/detection/status")
    assert detection.status_code == 200
    assert detection.json()["implemented"] is True
    for path in ("/ml", "/incidents", "/reports", "/live"):
        status = client.get(f"/api/v1{path}/status")
        assert status.status_code == 200
        assert status.json()["implemented"] is False


def test_api_rejects_unsafe_uploads(client, monkeypatch):
    source_id = _source(client, "limits")
    monkeypatch.setattr(get_settings(), "max_upload_bytes", 32)
    too_big = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("big.log", b"x" * 64, "text/plain")},
    )
    assert too_big.status_code == 400
    traversal = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("../../etc/passwd.log", b"hello", "text/plain")},
    )
    assert traversal.status_code == 400
    nul = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("x.log", b"\x00abc", "text/plain")},
    )
    assert nul.status_code == 400
    executable = client.post(
        f"/api/v1/sources/{source_id}/ingest/raw",
        files={"file": ("payload.exe", b"hello", "application/octet-stream")},
    )
    assert executable.status_code == 400
    duplicate = client.post("/api/v1/sources", json={"name": "limits"})
    assert duplicate.status_code == 409
