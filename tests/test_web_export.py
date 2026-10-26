import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from scanner.db.models import Base
from scanner.db.session import set_custom_engine
from scanner.history import save_scan
from scanner.models import ScanResult, Finding as PydanticFinding, Severity
from web.app import app, _login_attempts


@pytest.fixture(autouse=True)
def isolated_db():
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
    test_client = TestClient(app, client=("127.0.0.1", 50001), follow_redirects=False)
    login_page = test_client.get("/login")
    login_csrf = re.search(r"name='csrf_token' value='([^']+)'", login_page.text).group(1)
    test_client.post(
        "/login", data={"username": "test-user", "password": "test-password-only", "csrf_token": login_csrf}
    )
    page = test_client.get("/")
    test_client.headers["x-csrf-token"] = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    return test_client


def create_saved_scan():
    result = ScanResult(
        target="https://api.test.local",
        endpoints_scanned=2,
        unreachable_endpoints=0,
        findings=[
            PydanticFinding(
                severity=Severity.HIGH,
                title="Missing Security Headers",
                endpoint="https://api.test.local/v1/data",
                method="GET",
                owasp="API7:2023 Security Misconfiguration",
                description="Strict-Transport-Security header missing.",
                recommendation="Add Strict-Transport-Security header.",
            )
        ],
        discovery_source="OpenAPI",
        security_score=80.0,
        risk_level="LOW",
    )
    return save_scan(result, mode="passive")


def test_export_pdf_route(client):
    scan_record = create_saved_scan()
    response = client.get(f"/history/{scan_record.id}/export/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert f'filename="scan_{scan_record.id}_report.pdf"' in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF")


def test_export_html_route(client):
    scan_record = create_saved_scan()
    response = client.get(f"/history/{scan_record.id}/export/html")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert f'filename="scan_{scan_record.id}_report.html"' in response.headers["content-disposition"]
    assert "<!DOCTYPE html>" in response.text
    assert "Missing Security Headers" in response.text


def test_export_json_route(client):
    scan_record = create_saved_scan()
    response = client.get(f"/history/{scan_record.id}/export/json")

    assert response.status_code == 200
    assert "application/json" in response.headers["content-type"]
    assert f'filename="scan_{scan_record.id}_report.json"' in response.headers["content-disposition"]
    data = response.json()
    assert data["target"] == "https://api.test.local"
    assert len(data["findings"]) == 1


def test_export_sarif_route(client):
    scan_record = create_saved_scan()
    response = client.get(f"/history/{scan_record.id}/export/sarif")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/sarif+json")
    assert '"version": "2.1.0"' in response.text


def test_export_404_not_found(client):
    response = client.get("/history/99999/export/pdf")
    assert response.status_code == 404


def test_export_invalid_format(client):
    scan_record = create_saved_scan()
    response = client.get(f"/history/{scan_record.id}/export/xml")
    assert response.status_code == 400
