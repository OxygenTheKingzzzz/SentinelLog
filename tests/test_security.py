"""Request limits, CORS, and responses that do not leak tracebacks."""

from pathlib import Path

from fastapi.testclient import TestClient

from sentinellog.config import get_settings
from sentinellog.main import create_app
from sentinellog.ratelimit import bucket_for

ROOT = Path(__file__).resolve().parents[1]


def test_bucket_for_expensive_routes():
    assert bucket_for("POST", "/api/v1/sources/abc/ingest/raw") == "import"
    assert bucket_for("POST", "/api/v1/sources/abc/ingest/templates") == "import"
    assert bucket_for("POST", "/api/v1/sources/abc/ingest/structured") == "import"
    assert bucket_for("GET", "/api/v1/sources/abc/ingest/raw") is None
    assert bucket_for("POST", "/api/v1/detection/run") == "detect"
    assert bucket_for("POST", "/api/v1/ml/train") == "ml"
    assert bucket_for("POST", "/api/v1/ml/score") == "ml"
    assert bucket_for("POST", "/api/v1/risk/train") == "risk"
    assert bucket_for("POST", "/api/v1/risk/bands") == "risk"
    assert bucket_for("GET", "/api/v1/risk/predictions") is None
    assert bucket_for("GET", "/api/v1/ml/scores") is None
    assert bucket_for("GET", "/api/v1/investigations/abc/report.pdf") == "pdf"
    assert bucket_for("GET", "/api/v1/investigations/abc/evidence") is None
    assert bucket_for("GET", "/health") is None


def test_max_upload_bytes_reads_env(monkeypatch):
    monkeypatch.setenv("MAX_UPLOAD_BYTES", "2048")
    get_settings.cache_clear()
    try:
        assert get_settings().max_upload_bytes == 2048
    finally:
        get_settings.cache_clear()


def test_cors_origins_come_from_env(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "http://example.test")
    get_settings.cache_clear()
    try:
        app = create_app()
        with TestClient(app) as test_client:
            allowed = test_client.get("/health", headers={"Origin": "http://example.test"})
            assert allowed.status_code == 200
            assert allowed.headers["access-control-allow-origin"] == "http://example.test"
            blocked = test_client.get("/health", headers={"Origin": "http://evil.test"})
            assert blocked.status_code == 200
            assert "access-control-allow-origin" not in blocked.headers
    finally:
        get_settings.cache_clear()


def test_settings_reports_limits_without_secrets(client):
    payload = client.get("/api/v1/settings").json()
    assert payload["debug"] is False
    assert "http://127.0.0.1:5173" in payload["cors_origins"]
    assert payload["rate_limit_requests"] >= 1
    assert "password" not in payload
    assert "postgresql+psycopg://" not in client.get("/api/v1/settings").text


def test_rate_limit_returns_429(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_limit_requests", 2)
    first = client.post("/api/v1/detection/run")
    second = client.post("/api/v1/detection/run")
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    blocked = client.post("/api/v1/detection/run")
    assert blocked.status_code == 429
    assert blocked.json()["detail"] == "rate limit exceeded"
    assert blocked.headers["retry-after"]
    for _ in range(5):
        health = client.get("/health")
        assert health.status_code == 200


def test_debug_off_hides_traceback(monkeypatch):
    monkeypatch.setenv("DEBUG", "false")
    get_settings.cache_clear()
    try:
        app = create_app()

        @app.get("/boom")
        def boom() -> dict[str, str]:
            raise RuntimeError("secret marker")

        with TestClient(app, raise_server_exceptions=False) as test_client:
            response = test_client.get("/boom")
        assert response.status_code == 500
        assert response.headers["content-type"].startswith("application/json")
        assert response.json() == {"detail": "internal server error"}
        assert "secret marker" not in response.text
        assert "Traceback" not in response.text
    finally:
        get_settings.cache_clear()


def test_no_html_injection_or_shell_on_log_text():
    for path in (ROOT / "src").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "shell=True" not in source
        assert "os.system(" not in source
        assert "text(f" not in source
        assert "execute(f" not in source
        if "subprocess" in source:
            assert path.name == "journald.py"
    for path in (ROOT / "web" / "src").rglob("*"):
        if path.suffix not in {".ts", ".tsx", ".js", ".jsx"}:
            continue
        source = path.read_text(encoding="utf-8")
        assert "dangerouslySetInnerHTML" not in source
        assert ".innerHTML" not in source
