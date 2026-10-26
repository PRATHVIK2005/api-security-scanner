import json
from hashlib import sha256
from pathlib import Path

from jsonschema import Draft4Validator, FormatChecker

from scanner.models import Finding, ScanResult, Severity
from scanner.reports.sarif_report import generate_sarif_report


SARIF_SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))


def _validate_sarif(report: str) -> None:
    Draft4Validator.check_schema(SARIF_SCHEMA)
    Draft4Validator(SARIF_SCHEMA, format_checker=FormatChecker()).validate(json.loads(report))


def test_sarif_empty_and_partial_scans_are_well_formed():
    for status in ("complete", "partial", "interrupted"):
        result = ScanResult(target="https://api.example", endpoints_scanned=0, findings=[], scan_status=status)
        report = json.loads(generate_sarif_report(result))
        _validate_sarif(json.dumps(report))
        assert report["version"] == "2.1.0"
        run = report["runs"][0]
        assert run["results"] == []
        assert run["invocations"][0]["executionSuccessful"] is (status == "complete")


def test_sarif_maps_severity_fingerprints_locations_and_redacts_secrets():
    finding = Finding(
        severity=Severity.HIGH,
        title="Access token leaked",
        endpoint="https://api.example.test/items?api_key=private-value",
        method="GET",
        check_id="check.test.v1",
        finding_id="stable-id",
        confidence="medium",
        verification_status="potential",
    )
    result = ScanResult(target="https://api.example.test", endpoints_scanned=1, findings=[finding])
    data = json.loads(generate_sarif_report(result))
    _validate_sarif(json.dumps(data))
    item = data["runs"][0]["results"][0]
    assert item["level"] == "error"
    assert item["partialFingerprints"]["apiSecurity/v1"] == sha256(b"stable-id").hexdigest()
    assert item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("api_key=%5BREDACTED%5D")
    assert item["properties"]["verificationStatus"] == "potential"
    assert "private-value" not in generate_sarif_report(result)


def test_sarif_malformed_and_missing_endpoint_omit_invalid_location():
    finding = Finding(severity=Severity.INFO, title="Info", endpoint="not a uri", method="UNKNOWN")
    report = json.loads(generate_sarif_report(ScanResult(target="bad", endpoints_scanned=1, findings=[finding])))
    _validate_sarif(json.dumps(report))
    assert "locations" not in report["runs"][0]["results"][0]


def test_sarif_sanitizes_malformed_untrusted_identifiers_and_properties():
    finding = Finding(
        severity=Severity.INFO,
        title="Finding",
        endpoint="not a uri",
        method="Bearer private-token",
        check_id="Bearer private-rule-token",
        finding_id="Bearer private-fingerprint-token",
        confidence="private-confidence-token",
        verification_status="private-status-token",
    )
    report = generate_sarif_report(ScanResult(target="bad", endpoints_scanned=1, findings=[finding]))
    _validate_sarif(report)
    assert "private-token" not in report
    assert "private-rule-token" not in report
    assert "private-fingerprint-token" not in report
    assert "private-confidence-token" not in report
    assert "private-status-token" not in report
