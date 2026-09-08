from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from scanner.engine import scan, enrich_findings
from scanner.discovery import discover_endpoints
from scanner.models import ScanMode, Finding, Severity
from web.app import app


def test_authenticated_scan_engine_headers():
    with patch("scanner.engine.httpx.Client") as mock_client_cls, \
         patch("scanner.engine.discover_endpoints") as mock_discover:

        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_discover.return_value = MagicMock(endpoints=[], source="None", specification_url=None)

        result = scan(
            url="http://127.0.0.1:8000",
            mode=ScanMode.PASSIVE,
            token="secret-jwt-token-xyz",
            headers={"X-Custom-API-Key": "my-secret-key"},
        )

        mock_client_cls.assert_called_once()
        _, kwargs = mock_client_cls.call_args
        client_headers = kwargs.get("headers", {})

        # Verify Authorization: Bearer token is properly set
        assert client_headers.get("Authorization") == "Bearer secret-jwt-token-xyz"
        # Verify custom header is properly set
        assert client_headers.get("X-Custom-API-Key") == "my-secret-key"

        # Verify discover_endpoints received the client headers
        mock_discover.assert_called_once_with("http://127.0.0.1:8000", headers=client_headers)

        # Verify token and secrets are NOT stored or exposed in ScanResult
        assert "secret-jwt-token-xyz" not in str(result.model_dump())
        assert "my-secret-key" not in str(result.model_dump())


def test_discover_endpoints_passes_headers():
    with patch("scanner.discovery.httpx.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"paths": {}}
        mock_get.return_value = mock_resp

        auth_headers = {"Authorization": "Bearer test-token-123"}
        result = discover_endpoints("http://127.0.0.1:8000", headers=auth_headers)

        mock_get.assert_called()
        call_kwargs = mock_get.call_args.kwargs
        assert call_kwargs.get("headers") == auth_headers


def test_enrich_findings_preserves_existing_data():
    findings = [
        Finding(
            severity=Severity.HIGH,
            title="Broken Object Level Authorization (BOLA)",
            endpoint="http://api.local/item/1",
            owasp="CUSTOM-OWASP-CODE",
            description="Custom description that should not be overwritten",
            recommendation="Custom recommendation that should not be overwritten",
        )
    ]

    enriched = enrich_findings(findings)
    assert enriched[0].owasp == "CUSTOM-OWASP-CODE"
    assert enriched[0].description == "Custom description that should not be overwritten"
    assert enriched[0].recommendation == "Custom recommendation that should not be overwritten"


def test_web_scan_does_not_leak_bearer_token():
    client = TestClient(app)
    with patch("web.app.scan") as mock_scan:
        from scanner.models import ScanResult
        mock_scan.return_value = ScanResult(
            target="http://127.0.0.1:8000",
            endpoints_scanned=1,
            findings=[],
            security_score=100.0,
            risk_level="LOW",
        )

        response = client.post(
            "/scan",
            data={
                "url": "http://127.0.0.1:8000",
                "mode": "passive",
                "token": "super-secret-jwt-token-9999",
            },
        )
        assert response.status_code == 200
        # The raw token MUST NOT appear anywhere in the rendered HTML output
        assert "super-secret-jwt-token-9999" not in response.text
        # But auth indicator should be active
        assert "AUTH: BEARER TOKEN ACTIVE" in response.text


def test_web_scan_url_scheme_validation():
    client = TestClient(app)
    response = client.post(
        "/scan",
        data={
            "url": "ftp://malicious.host/file",
            "mode": "passive",
        },
    )
    assert response.status_code == 200
    assert "Invalid URL. Only http:// and https:// targets are supported." in response.text

