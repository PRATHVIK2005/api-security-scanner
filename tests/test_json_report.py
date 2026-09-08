import json

from scanner.models import (
    Finding,
    ScanResult,
    Severity,
)
from scanner.reports.json_report import (
    generate_json_report,
)


def make_result() -> ScanResult:

    finding = Finding(
        title="Test Finding",
        severity=Severity.HIGH,
        description="Test description",
        endpoint="https://api.example.com/users",
        remediation="Fix the issue",
        method="GET",
    )

    return ScanResult(
        target="https://api.example.com",
        endpoints_scanned=1,
        unreachable_endpoints=0,
        findings=[finding],
        discovery_source="OpenAPI",
        specification_url=(
            "https://api.example.com/openapi.json"
        ),
        security_score=85,
        risk_level="LOW",
    )


def test_generate_json_report():

    result = make_result()

    report = generate_json_report(result)

    data = json.loads(report)

    assert data["target"] == (
        "https://api.example.com"
    )

    assert data["security_score"] == 85

    assert data["risk_level"] == "LOW"

    assert len(data["findings"]) == 1

    assert data["findings"][0]["severity"] == "HIGH"


def test_json_report_contains_discovery_data():

    result = make_result()

    report = generate_json_report(result)

    data = json.loads(report)

    assert data["discovery_source"] == "OpenAPI"

    assert data["specification_url"] == (
        "https://api.example.com/openapi.json"
    )