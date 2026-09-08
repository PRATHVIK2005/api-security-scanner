import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from scanner.db.models import Base
from scanner.db.session import set_custom_engine
from scanner.history import save_scan
from scanner.models import ScanResult, Finding as PydanticFinding, Severity
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


def test_export_404_not_found(client):
    response = client.get("/history/99999/export/pdf")
    assert response.status_code == 404


def test_export_invalid_format(client):
    scan_record = create_saved_scan()
    response = client.get(f"/history/{scan_record.id}/export/xml")
    assert response.status_code == 400
