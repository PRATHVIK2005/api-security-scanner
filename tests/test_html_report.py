import pytest
from pathlib import Path
from scanner.models import Finding, ScanResult, Severity
from scanner.reports.html_report import generate_html_report


def sample_scan_result() -> ScanResult:
    return ScanResult(
        target="https://api.example.com",
        endpoints_scanned=3,
        unreachable_endpoints=0,
        findings=[
            Finding(
                severity=Severity.HIGH,
                title="CORS Wildcard with Credentials",
                endpoint="https://api.example.com/data",
                method="GET",
                owasp="API7:2023 Security Misconfiguration",
                description="Access-Control-Allow-Origin is set to wildcard with credentials.",
                recommendation="Specify exact trusted origins.",
            )
        ],
        discovery_source="OpenAPI Spec",
        specification_url=None,
        security_score=72.5,
        risk_level="MEDIUM",
    )


def test_generate_html_report_content():
    result = sample_scan_result()
    html_str = generate_html_report(result)

    assert isinstance(html_str, str)
    assert "<!DOCTYPE html>" in html_str
    assert "https://api.example.com" in html_str
    assert "72.5" in html_str
    assert "CORS Wildcard with Credentials" in html_str
    assert "API7:2023 Security Misconfiguration" in html_str
    assert "Specify exact trusted origins." in html_str


def test_generate_html_report_file_output(tmp_path: Path):
    result = sample_scan_result()
    output_file = tmp_path / "test_report.html"

    html_str = generate_html_report(result, output_path=output_file)

    assert output_file.exists()
    assert output_file.read_text(encoding="utf-8") == html_str
