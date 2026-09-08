from unittest.mock import patch
import pytest
from typer.testing import CliRunner

from cli.main import app
from scanner.models import Finding, ScanResult, Severity

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "history" in result.stdout
    assert "compare" in result.stdout


def test_cli_scan_help():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--url" in result.stdout
    assert "--mode" in result.stdout
    assert "--token" in result.stdout
    assert "--format" in result.stdout


def test_cli_scan_invalid_url():
    result = runner.invoke(app, ["scan", "--url", "not-a-valid-url"])
    assert result.exit_code == 1
    assert "Validation Error" in result.stdout or "Invalid" in result.stdout


def test_cli_scan_invalid_format():
    result = runner.invoke(app, ["scan", "--url", "http://127.0.0.1:8000", "--format", "xml"])
    assert result.exit_code == 1
    assert "Invalid format" in result.stdout


def test_cli_scan_success_terminal():
    mock_result = ScanResult(
        target="http://127.0.0.1:8000",
        endpoints_scanned=2,
        unreachable_endpoints=0,
        findings=[
            Finding(
                severity=Severity.LOW,
                title="Missing X-Frame-Options Header",
                endpoint="http://127.0.0.1:8000/",
                method="GET",
            )
        ],
        discovery_source="OpenAPI",
        security_score=97.0,
        risk_level="LOW",
        scan_mode="passive",
    )

    with patch("cli.main.scan", return_value=mock_result):
        result = runner.invoke(app, ["scan", "--url", "http://127.0.0.1:8000"])
        assert result.exit_code == 0
        assert "API Security Scan Results" in result.stdout
        assert "97.0/100" in result.stdout
        assert "Missing X-Frame-Options Header" in result.stdout


def test_cli_scan_json_output():
    mock_result = ScanResult(
        target="http://127.0.0.1:8000",
        endpoints_scanned=1,
        unreachable_endpoints=0,
        findings=[],
        discovery_source="OpenAPI",
        security_score=100.0,
        risk_level="LOW",
        scan_mode="passive",
    )

    with patch("cli.main.scan", return_value=mock_result):
        result = runner.invoke(app, ["scan", "--url", "http://127.0.0.1:8000", "--format", "json"])
        assert result.exit_code == 0
        assert '"target": "http://127.0.0.1:8000"' in result.stdout


def test_cli_history_empty():
    with patch("scanner.history.get_all_scans", return_value=[]):
        result = runner.invoke(app, ["history"])
        assert result.exit_code == 0
        assert "No past scans found" in result.stdout


def test_cli_compare_not_found():
    with patch("scanner.history.compare_scans", return_value=None):
        result = runner.invoke(app, ["compare", "999", "998"])
        assert result.exit_code == 1
        assert "Error:" in result.stdout
