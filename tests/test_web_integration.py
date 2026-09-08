from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from scanner.db.models import Base
from scanner.db.session import set_custom_engine
from scanner.models import Finding, ScanMode, ScanResult, Severity
from web.app import app


@pytest.fixture(autouse=True)
def isolated_db():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    set_custom_engine(test_engine)
    yield test_engine
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    return TestClient(app)


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
        target="https://api.example.com",
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
                "url": "https://api.example.com",
                "mode": "active",
            },
        )

        assert response.status_code == 200
        mock_scan.assert_called_once_with(
            url="https://api.example.com",
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


def test_unreachable_api_handled_gracefully(client):
    """8. Unreachable targets return appropriate result or error message."""
    mock_result = ScanResult(
        target="http://192.0.2.1:8000",
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
                "url": "http://192.0.2.1:8000",
                "mode": "passive",
            },
        )
        assert response.status_code == 200
        assert "Unreachable" in response.text or "1" in response.text


def test_authentication_input_passed_to_scanner(client):
    """9. Authentication token is securely passed to scanner and never echoed back in HTML."""
    mock_result = ScanResult(
        target="https://api.example.com",
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
                "url": "https://api.example.com",
                "mode": "passive",
                "token": secret_jwt,
            },
        )

        assert response.status_code == 200
        mock_scan.assert_called_once_with(
            url="https://api.example.com",
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
