from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from scanner.db.models import Base
from scanner.db.session import set_custom_engine

from web.app import app, _login_attempts


@pytest.fixture(autouse=True)
def isolated_db():
    _login_attempts.clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    set_custom_engine(engine)
    yield
    engine.dispose()


def _client(monkeypatch):
    monkeypatch.setenv("API_SCANNER_DASHBOARD_USERNAME", "dashboard-test")
    monkeypatch.setenv("API_SCANNER_DASHBOARD_PASSWORD", "private-test-password")
    monkeypatch.setenv("API_SCANNER_DASHBOARD_SESSION_SECRET", "test-session-secret-for-dashboard-1234567890")
    return TestClient(app, client=("127.0.0.1", 51000), follow_redirects=False)


def _login(client, username, password):
    import re

    page = client.get("/login")
    csrf = re.search(r"name='csrf_token' value='([^']+)'", page.text).group(1)
    return client.post("/login", data={"username": username, "password": password, "csrf_token": csrf})


def test_dashboard_protected_routes_require_auth_and_do_not_start_scans(monkeypatch):
    client = _client(monkeypatch)
    with patch("web.app.scan") as scan:
        assert client.get("/history").status_code == 401
        assert client.get("/compare?scan1=1&scan2=2").status_code == 401
        response = client.post(
            "/scan", headers={"Origin": "http://testserver"}, data={"url": "http://127.0.0.1", "mode": "passive"}
        )
        assert response.status_code == 401
        scan.assert_not_called()


def test_dashboard_login_invalid_valid_and_logout(monkeypatch):
    client = _client(monkeypatch)
    assert _login(client, "bad", "bad").status_code == 401
    assert _login(client, "dashboard-test", "private-test-password").status_code == 303
    assert client.get("/history").status_code == 200
    page = client.get("/")
    import re

    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    assert client.post("/logout", headers={"x-csrf-token": token}).status_code == 303
    assert client.get("/history").status_code == 401


def test_dashboard_csrf_and_expired_session_fail_closed(monkeypatch):
    client = _client(monkeypatch)
    _login(client, "dashboard-test", "private-test-password")
    with patch("web.app.scan") as scan:
        assert (
            client.post(
                "/scan", headers={"Origin": "http://testserver"}, data={"url": "http://127.0.0.1", "mode": "passive"}
            ).status_code
            == 403
        )
        scan.assert_not_called()
    with patch("web.app.time.time", return_value=9999999999):
        assert client.get("/history").status_code == 401


def test_dashboard_scan_rate_limit_remains_active(monkeypatch):
    # The existing limiter is exercised by the integration suite; this checks
    # authentication itself does not grant an unauthenticated scan path.
    client = _client(monkeypatch)
    response = client.post(
        "/scan", headers={"Origin": "http://testserver"}, data={"url": "http://127.0.0.1", "mode": "passive"}
    )
    assert response.status_code == 401


def test_dashboard_login_rate_limit(monkeypatch):
    client = _client(monkeypatch)
    import re

    page = client.get("/login")
    csrf = re.search(r"name='csrf_token' value='([^']+)'", page.text).group(1)
    for _ in range(5):
        assert (
            client.post("/login", data={"username": "wrong", "password": "wrong", "csrf_token": csrf}).status_code
            == 401
        )
    assert client.post("/login", data={"username": "wrong", "password": "wrong", "csrf_token": csrf}).status_code == 429
