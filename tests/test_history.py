"""Tests for SQLite scan history, details, and comparison features."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from scanner.db.models import Base, Scan, Finding
from scanner.db.session import set_custom_engine, get_session_factory
from scanner.history import (
    save_scan,
    get_all_scans,
    get_scan_by_id,
    compare_scans,
    count_severity_breakdown,
)
from scanner.models import ScanResult, Finding as PydanticFinding, Severity
from web.app import app


@pytest.fixture(autouse=True)
def isolated_db():
    """Use an isolated in-memory SQLite database for each test."""
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
def sample_findings():
    return [
        PydanticFinding(
            severity=Severity.HIGH,
            title="Broken Object Level Authorization (BOLA)",
            endpoint="http://api.local/users/123",
            method="GET",
            owasp="API1:2023 - Broken Object Level Authorization",
            description="Unauthorized user can access resource 123",
            recommendation="Implement object-level access control checks.",
        ),
        PydanticFinding(
            severity=Severity.MEDIUM,
            title="Missing Security Headers",
            endpoint="http://api.local/users/123",
            method="GET",
            owasp="API8:2023 - Security Misconfiguration",
            description="Strict-Transport-Security header is missing",
            recommendation="Configure HSTS with max-age header.",
        ),
        PydanticFinding(
            severity=Severity.LOW,
            title="Server Header Disclosure",
            endpoint="http://api.local/info",
            method="GET",
            owasp="API8:2023 - Security Misconfiguration",
            description="Exposes exact server version",
            recommendation="Disable Server banner in reverse proxy.",
        ),
    ]


@pytest.fixture
def sample_scan_result(sample_findings):
    return ScanResult(
        target="http://api.local",
        endpoints_scanned=5,
        findings=sample_findings,
        security_score=68.5,
        risk_level="MEDIUM",
    )


def test_save_scan_and_findings(sample_scan_result):
    """Test saving a scan and its associated findings to SQLite."""
    saved = save_scan(sample_scan_result, mode="passive")

    assert saved.id is not None
    assert saved.target_url == "http://api.local"
    assert saved.security_score == 68.5
    assert saved.risk_level == "MEDIUM"
    assert saved.scan_mode == "passive"
    assert saved.findings_count == 3
    assert len(saved.findings) == 3

    finding = saved.findings[0]
    assert finding.severity == "HIGH"
    assert finding.title == "Broken Object Level Authorization (BOLA)"
    assert finding.method == "GET"
    assert finding.endpoint == "http://api.local/users/123"
    assert "API1:2023" in finding.owasp
    assert finding.description is not None
    assert finding.recommendation is not None


def test_database_relationships(sample_scan_result):
    """Test relationships and cascading delete behavior."""
    saved = save_scan(sample_scan_result, mode="active")
    scan_id = saved.id

    SessionLocal = get_session_factory()
    session = SessionLocal()

    scan_rec = session.query(Scan).filter(Scan.id == scan_id).first()
    assert scan_rec is not None
    assert len(scan_rec.findings) == 3

    # Verify back-reference
    assert scan_rec.findings[0].scan.id == scan_id

    # Verify cascade delete: deleting scan removes findings
    session.delete(scan_rec)
    session.commit()

    orphan_findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
    assert len(orphan_findings) == 0
    session.close()


def test_get_all_scans_ordering():
    """Test retrieving scan history sorted by date descending."""
    sr1 = ScanResult(
        target="http://api1.local",
        endpoints_scanned=2,
        findings=[],
        security_score=100.0,
        risk_level="LOW",
    )
    sr2 = ScanResult(
        target="http://api2.local",
        endpoints_scanned=3,
        findings=[],
        security_score=75.0,
        risk_level="MEDIUM",
    )

    save_scan(sr1, mode="passive")
    save_scan(sr2, mode="active")

    scans = get_all_scans()
    assert len(scans) == 2
    # Newest scan is first
    assert scans[0].target_url == "http://api2.local"
    assert scans[1].target_url == "http://api1.local"


def test_get_scan_by_id():
    """Test retrieving specific scan by ID and nonexistent ID handling."""
    sr = ScanResult(
        target="http://api-unique.local",
        endpoints_scanned=1,
        findings=[],
        security_score=90.0,
        risk_level="LOW",
    )
    saved = save_scan(sr, mode="passive")

    found = get_scan_by_id(saved.id)
    assert found is not None
    assert found.target_url == "http://api-unique.local"

    not_found = get_scan_by_id(99999)
    assert not_found is None


def test_count_severity_breakdown():
    """Test counting findings by severity level."""
    findings = [
        Finding(severity="CRITICAL", title="T1", endpoint="/1"),
        Finding(severity="HIGH", title="T2", endpoint="/2"),
        Finding(severity="HIGH", title="T3", endpoint="/3"),
        Finding(severity="LOW", title="T4", endpoint="/4"),
    ]
    counts = count_severity_breakdown(findings)
    assert counts["CRITICAL"] == 1
    assert counts["HIGH"] == 2
    assert counts["MEDIUM"] == 0
    assert counts["LOW"] == 1


def test_compare_scans_improved():
    """Test comparing two scans when security has improved."""
    sr1 = ScanResult(
        target="http://api.local",
        endpoints_scanned=4,
        findings=[
            PydanticFinding(severity=Severity.HIGH, title="High Issue", endpoint="/api")
        ],
        security_score=60.0,
        risk_level="HIGH",
    )
    sr2 = ScanResult(
        target="http://api.local",
        endpoints_scanned=4,
        findings=[],
        security_score=95.0,
        risk_level="LOW",
    )

    s1 = save_scan(sr1, mode="passive")
    s2 = save_scan(sr2, mode="passive")

    comparison = compare_scans(s1.id, s2.id)
    assert comparison is not None
    assert comparison["score_diff"] == 35.0
    assert comparison["findings_diff"] == -1
    assert comparison["status"] == "IMPROVED"
    assert comparison["severity_diff"]["HIGH"] == -1


def test_compare_scans_worsened():
    """Test comparing two scans when security has worsened."""
    sr1 = ScanResult(
        target="http://api.local",
        endpoints_scanned=2,
        findings=[],
        security_score=100.0,
        risk_level="LOW",
    )
    sr2 = ScanResult(
        target="http://api.local",
        endpoints_scanned=2,
        findings=[
            PydanticFinding(severity=Severity.CRITICAL, title="Critical Issue", endpoint="/login")
        ],
        security_score=40.0,
        risk_level="CRITICAL",
    )

    s1 = save_scan(sr1, mode="passive")
    s2 = save_scan(sr2, mode="active")

    comparison = compare_scans(s1.id, s2.id)
    assert comparison is not None
    assert comparison["score_diff"] == -60.0
    assert comparison["findings_diff"] == 1
    assert comparison["status"] == "WORSENED"
    assert comparison["severity_diff"]["CRITICAL"] == 1


def test_compare_scans_unchanged():
    """Test comparing two scans with identical score and findings count."""
    sr = ScanResult(
        target="http://api.local",
        endpoints_scanned=2,
        findings=[],
        security_score=85.0,
        risk_level="LOW",
    )
    s1 = save_scan(sr, mode="passive")
    s2 = save_scan(sr, mode="passive")

    comparison = compare_scans(s1.id, s2.id)
    assert comparison is not None
    assert comparison["score_diff"] == 0.0
    assert comparison["findings_diff"] == 0
    assert comparison["status"] == "UNCHANGED"


def test_compare_scans_missing_id():
    """Test comparing nonexistent scan IDs returns None."""
    assert compare_scans(1234, 5678) is None


# ==========================================
# FASTAPI WEB ROUTES TESTS
# ==========================================

client = TestClient(app)


def test_web_history_route():
    """Test GET /history page returns 200."""
    response = client.get("/history")
    assert response.status_code == 200
    assert "Scan History" in response.text


def test_web_scan_details_route(sample_scan_result):
    """Test GET /history/{id} displays scan information and findings."""
    saved = save_scan(sample_scan_result, mode="passive")

    response = client.get(f"/history/{saved.id}")
    assert response.status_code == 200
    assert "Broken Object Level Authorization (BOLA)" in response.text
    assert "http://api.local/users/123" in response.text
    assert "68.5" in response.text


def test_web_scan_details_404():
    """Test GET /history/{id} returns 404 for invalid scan ID."""
    response = client.get("/history/99999")
    assert response.status_code == 404


def test_web_compare_route():
    """Test GET /compare with two valid scan IDs."""
    sr1 = ScanResult(target="http://api.local", endpoints_scanned=1, findings=[], security_score=50.0, risk_level="HIGH")
    sr2 = ScanResult(target="http://api.local", endpoints_scanned=1, findings=[], security_score=80.0, risk_level="LOW")
    s1 = save_scan(sr1)
    s2 = save_scan(sr2)

    response = client.get(f"/compare?scan1={s1.id}&scan2={s2.id}")
    assert response.status_code == 200
    assert "POSTURE ASSESSMENT" in response.text
    assert "+30.0" in response.text


def test_web_compare_missing_404():
    """Test GET /compare returns 404 if either scan does not exist."""
    response = client.get("/compare?scan1=1&scan2=99999")
    assert response.status_code == 404


def test_save_scan_metadata_columns():
    """Test that endpoints_scanned, unreachable_endpoints, discovery_source, specification_url are saved."""
    sr = ScanResult(
        target="http://api.local",
        endpoints_scanned=12,
        unreachable_endpoints=2,
        findings=[],
        discovery_source="OpenAPI Spec",
        specification_url="http://api.local/openapi.json",
        security_score=88.0,
        risk_level="LOW",
        scan_mode="active",
    )
    saved = save_scan(sr, mode="active")
    retrieved = get_scan_by_id(saved.id)

    assert retrieved is not None
    assert retrieved.endpoints_scanned == 12
    assert retrieved.unreachable_endpoints == 2
    assert retrieved.discovery_source == "OpenAPI Spec"
    assert retrieved.specification_url == "http://api.local/openapi.json"
    assert retrieved.scan_mode == "active"

