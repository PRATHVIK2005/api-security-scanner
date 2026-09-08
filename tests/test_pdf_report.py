import pytest
from pathlib import Path
from scanner.models import Finding, ScanResult, Severity
from scanner.reports.pdf_report import generate_pdf_report


def sample_scan_result() -> ScanResult:
    return ScanResult(
        target="https://api.example.com",
        endpoints_scanned=5,
        unreachable_endpoints=0,
        findings=[
            Finding(
                severity=Severity.CRITICAL,
                title="BOLA Vulnerability in User Endpoint",
                endpoint="https://api.example.com/users/{id}",
                method="GET",
                owasp="API1:2023 Broken Object Level Authorization",
                description="Endpoint allows unauthorized user ID traversal.",
                recommendation="Implement object-level authorization checks.",
            ),
            Finding(
                severity=Severity.MEDIUM,
                title="Missing Rate Limiting",
                endpoint="https://api.example.com/login",
                method="POST",
                owasp="API4:2023 Unrestricted Resource Consumption",
                description="No rate limiting headers detected.",
                recommendation="Configure rate limiting middleware.",
            ),
        ],
        discovery_source="OpenAPI Spec",
        specification_url="https://api.example.com/openapi.json",
        security_score=55.0,
        risk_level="MEDIUM",
    )


def test_generate_pdf_report_bytes():
    result = sample_scan_result()
    pdf_bytes = generate_pdf_report(result)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
    # Check PDF file magic header
    assert pdf_bytes.startswith(b"%PDF")


def test_generate_pdf_report_file_output(tmp_path: Path):
    result = sample_scan_result()
    output_file = tmp_path / "test_report.pdf"

    pdf_bytes = generate_pdf_report(result, output_path=output_file)

    assert output_file.exists()
    assert output_file.stat().st_size > 0
    with open(output_file, "rb") as f:
        content = f.read()
    assert content.startswith(b"%PDF")


def test_generate_pdf_report_active_mode():
    result = sample_scan_result()
    result.scan_mode = "active"
    pdf_bytes = generate_pdf_report(result, scan_mode="active")

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")

