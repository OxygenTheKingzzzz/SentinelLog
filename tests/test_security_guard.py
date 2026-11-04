import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sentinellog.security import SecurityMiddleware


@pytest.fixture
def guarded():
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, token="test-admin", max_bytes=16)

    @app.api_route("/events", methods=["GET", "POST"])
    def events():
        return {"ok": True}

    return TestClient(app)


def test_public_read_and_security_headers(guarded):
    result = guarded.get("/events")
    assert result.status_code == 200
    assert result.headers["x-content-type-options"] == "nosniff"
    assert result.headers["cache-control"] == "no-store"


def test_writes_require_admin_before_body_parsing(guarded):
    assert guarded.post("/events", content="malicious data").status_code == 401
    assert guarded.post("/events", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert (
        guarded.post("/events", headers={"Authorization": "Bearer test-admin"}).status_code == 200
    )


def test_body_limit(guarded):
    assert (
        guarded.post(
            "/events", content="a" * 17, headers={"Authorization": "Bearer test-admin"}
        ).status_code
        == 413
    )


def test_request_flood_is_bounded(guarded):
    for _ in range(120):
        assert guarded.get("/events").status_code == 200
    assert guarded.get("/events").status_code == 429


def test_no_configured_secret_fails_closed():
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, token="", max_bytes=16)
    assert TestClient(app).post("/events").status_code == 401


def test_chunked_upload_limit(guarded):
    assert (
        guarded.post(
            "/events",
            content=iter([b"a" * 10, b"b" * 10]),
            headers={"Authorization": "Bearer test-admin"},
        ).status_code
        == 413
    )


def test_private_configuration_requires_token(guarded):
    assert guarded.get("/api/v1/settings").status_code == 401
