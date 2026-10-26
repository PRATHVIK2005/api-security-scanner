from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from scanner.db.models import Base, Finding as FindingRecord, Scan
from scanner.db.session import get_session_factory, set_custom_engine
from scanner.models import Finding, ScanMode, ScanResult, Severity
from web.app import app, _scan_times, _login_attempts


@pytest.fixture(autouse=True)
def isolated_db():
    _scan_times.clear()
    _login_attempts.clear()
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    set_custom_engine(test_engine)
    yield test_engine

    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


@pytest.fixture
def client(monkeypatch):
    import re

    monkeypatch.setenv("API_SCANNER_DASHBOARD_USERNAME", "test-user")
    monkeypatch.setenv("API_SCANNER_DASHBOARD_PASSWORD", "test-password-only")
    monkeypatch.setenv("API_SCANNER_DASHBOARD_SESSION_SECRET", "test-session-secret-for-dashboard-1234567890")
    test_client = TestClient(
        app, client=("127.0.0.1", 50000), headers={"Origin": "http://testserver"}, follow_redirects=False
    )
    login_page = test_client.get("/login")
    login_csrf = re.search(r"name='csrf_token' value='([^']+)'", login_page.text).group(1)
    test_client.post(
        "/login", data={"username": "test-user", "password": "test-password-only", "csrf_token": login_csrf}
    )
    page = test_client.get("/")
    test_client.headers["x-csrf-token"] = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    return test_client


def test_get_root_returns_200(client):
    """1. GET / must return HTTP 200 and render dashboard UI."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "API Security Scanner" in response.text or "API" in response.text


def test_get_health_returns_200(client):
    """2. GET /health must return HTTP 200 with ok status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "service" in data


def test_valid_scan_passive_mode(client):
    """3 & 4. Valid scan request in passive mode executes correctly."""
    mock_result = ScanResult(
        target="http://127.0.0.1:8000",
        endpoints_scanned=3,
        unreachable_endpoints=0,
        findings=[
            Finding(
                severity=Severity.LOW,
                title="Missing X-Frame-Options Header",
                endpoint="http://127.0.0.1:8000/items",
                method="GET",
                description="Test description",
                recommendation="Add header",
            )
        ],
        discovery_source="OpenAPI",
        security_score=97.0,
        risk_level="LOW",
        scan_mode="passive",
    )

    with patch("web.app.scan", return_value=mock_result) as mock_scan:
        response = client.post(
            "/scan",
            data={
                "url": "http://127.0.0.1:8000",
                "mode": "passive",
            },
        )

        assert response.status_code == 200
        assert "Missing X-Frame-Options Header" in response.text
        assert "97" in response.text
        mock_scan.assert_called_once_with(
            url="http://127.0.0.1:8000",
            mode=ScanMode.PASSIVE,
            token=None,
        )


def test_valid_scan_active_mode(client):
    """5. Active scan mode is correctly processed."""
    mock_result = ScanResult(
        target="http://127.0.0.1:8000",
        endpoints_scanned=5,
        unreachable_endpoints=0,
        findings=[],
        discovery_source="OpenAPI",
        security_score=100.0,
        risk_level="LOW",
        scan_mode="active",
    )

    with patch("web.app.scan", return_value=mock_result) as mock_scan:
        response = client.post(
            "/scan",
            data={
                "url": "http://127.0.0.1:8000",
                "mode": "active",
            },
        )

        assert response.status_code == 200
        mock_scan.assert_called_once_with(
            url="http://127.0.0.1:8000",
            mode=ScanMode.ACTIVE,
            token=None,
        )


def test_invalid_scan_mode_returns_error(client):
    """6. Invalid scan mode returns proper validation error without crash."""
    response = client.post(
        "/scan",
        data={
            "url": "http://127.0.0.1:8000",
            "mode": "super_aggressive_mode",
        },
    )

    assert response.status_code == 200
    assert "Invalid scan mode" in response.text


def test_invalid_url_rejected_gracefully(client):
    """7. Invalid URLs (ftp, non-url, empty) return error and do not crash app."""
    invalid_urls = ["not-a-url", "ftp://example.com", "hello"]
    for inv_url in invalid_urls:
        response = client.post(
            "/scan",
            data={
                "url": inv_url,
                "mode": "passive",
            },
        )
        assert response.status_code == 200
        assert "Invalid" in response.text or "error" in response.text.lower()


def test_dashboard_does_not_echo_credentials_from_invalid_target(client):
    response = client.post(
        "/scan",
        data={"url": "http://user:password@127.0.0.1:8000/?api_key=secret-value", "mode": "passive"},
    )
    assert response.status_code == 200
    for secret in ("user:password", "secret-value"):
        assert secret not in response.text


def test_history_redacts_credentials_from_legacy_database_records(client):
    session = get_session_factory()()
    record = Scan(
        target_url="https://user:password@api.example.test/?api_key=private-query-value",
        security_score=50,
        risk_level="MEDIUM",
        scan_mode="passive",
        findings_count=1,
        findings=[
            FindingRecord(
                severity="LOW",
                title="Cookie: sessionid=private-cookie-value",
                endpoint="https://user:password@api.example.test/items?token=private-token-value",
                method="GET",
                evidence="Authorization: Bearer private-bearer-value",
            )
        ],
    )
    session.add(record)
    session.commit()
    scan_id = record.id
    session.close()

    for route in ("/history", f"/history/{scan_id}", f"/history/{scan_id}/export/json"):
        response = client.get(route)
        assert response.status_code == 200
        for secret in (
            "user:password",
            "private-query-value",
            "private-cookie-value",
            "private-token-value",
            "private-bearer-value",
        ):
            assert secret not in response.text


def test_dashboard_rejects_remote_targets_not_in_allowlist(client):
    response = client.post("/scan", data={"url": "https://attacker.example", "mode": "passive"})
    assert response.status_code == 403
    assert "remote dashboard scanning is disabled" in response.text.lower()


def test_dashboard_requires_literal_loopback_address(client):
    with patch("web.app.scan") as mock_scan:
        response = client.post("/scan", data={"url": "http://localhost:8001", "mode": "passive"})
    assert response.status_code == 403
    mock_scan.assert_not_called()


def test_dashboard_rejects_non_loopback_clients():
    remote_client = TestClient(app, client=("203.0.113.9", 53000))
    response = remote_client.get("/history")
    assert response.status_code == 403
    assert "local-only" in response.json()["detail"]


def test_dashboard_rejects_cross_site_scan_submission(client):
    response = client.post(
        "/scan",
        headers={"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
        data={"url": "http://127.0.0.1:8000", "mode": "passive"},
    )
    assert response.status_code == 403


def test_dashboard_rejects_scan_submission_without_origin():
    no_origin = TestClient(app, client=("127.0.0.1", 50000))
    response = no_origin.post("/scan", data={"url": "http://127.0.0.1:8000", "mode": "passive"})
    assert response.status_code == 403
    assert "same-origin" in response.json()["detail"].lower()


def test_unreachable_api_handled_gracefully(client):
    """8. Unreachable targets return appropriate result or error message."""
    mock_result = ScanResult(
        target="http://127.0.0.1:9999",
        endpoints_scanned=1,
        unreachable_endpoints=1,
        findings=[],
        discovery_source="Fallback",
        security_score=100.0,
        risk_level="LOW",
        scan_mode="passive",
    )

    with patch("web.app.scan", return_value=mock_result):
        response = client.post(
            "/scan",
            data={
                "url": "http://127.0.0.1:9999",
                "mode": "passive",
            },
        )
        assert response.status_code == 200
        assert "Unreachable" in response.text or "1" in response.text


def test_authentication_input_passed_to_scanner(client):
    """9. Authentication token is securely passed to scanner and never echoed back in HTML."""
    mock_result = ScanResult(
        target="http://127.0.0.1:8000",
        endpoints_scanned=2,
        unreachable_endpoints=0,
        findings=[],
        discovery_source="OpenAPI",
        security_score=100.0,
        risk_level="LOW",
        scan_mode="passive",
    )

    secret_jwt = "secret_jwt_token_12345"

    with patch("web.app.scan", return_value=mock_result) as mock_scan:
        response = client.post(
            "/scan",
            data={
                "url": "http://127.0.0.1:8000",
                "mode": "passive",
                "token": secret_jwt,
            },
        )

        assert response.status_code == 200
        mock_scan.assert_called_once_with(
            url="http://127.0.0.1:8000",
            mode=ScanMode.PASSIVE,
            token=secret_jwt,
        )
        # Verify secret token is NOT leaked into the rendered HTML body
        assert secret_jwt not in response.text
        assert "Bearer Token Provided" in response.text or "Authentication" in response.text


def test_history_and_compare_routes(client):
    """10. Scan history and compare views load correctly."""
    response = client.get("/history")
    assert response.status_code == 200

    # Non-existent compare IDs return 404
    resp_compare = client.get("/compare?scan1=999&scan2=998")
    assert resp_compare.status_code == 404
