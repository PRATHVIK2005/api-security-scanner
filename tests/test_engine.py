from unittest.mock import Mock, patch

from scanner.engine import (
    ACTIVE_METHODS,
    PASSIVE_METHODS,
    scan,
)
from scanner.models import (
    DiscoveryResult,
    Endpoint,
    ScanMode,
)


def test_passive_methods():
    assert "GET" in PASSIVE_METHODS
    assert "HEAD" in PASSIVE_METHODS
    assert "OPTIONS" in PASSIVE_METHODS

    assert "POST" not in PASSIVE_METHODS
    assert "PUT" not in PASSIVE_METHODS
    assert "PATCH" not in PASSIVE_METHODS
    assert "DELETE" not in PASSIVE_METHODS


def test_active_methods():
    assert "GET" in ACTIVE_METHODS
    assert "POST" not in ACTIVE_METHODS
    assert "PUT" not in ACTIVE_METHODS
    assert "PATCH" not in ACTIVE_METHODS
    assert "DELETE" not in ACTIVE_METHODS


@patch("scanner.engine.create_scanner_client")
@patch("scanner.engine.discover_endpoints")
def test_engine_detects_bola_risk(
    mock_discover_endpoints,
    mock_client,
):

    endpoint = Endpoint(
        url="https://api.example.com/users/{id}",
        method="GET",
        path="/users/{id}",
        requires_auth=False,
    )

    mock_discover_endpoints.return_value = DiscoveryResult(
        endpoints=[endpoint],
        source="OpenAPI",
        specification_url="https://api.example.com/openapi.json",
    )

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.text = ""

    mock_client_instance = Mock()
    mock_client_instance.request.return_value = mock_response
    mock_client_instance.get.return_value = mock_response
    mock_client_instance.options.return_value = mock_response

    mock_client.return_value = mock_client_instance

    result = scan(
        url="https://api.example.com",
        mode=ScanMode.PASSIVE,
    )

    titles = [finding.title for finding in result.findings]

    assert "Potential Broken Object Level Authorization" in titles


@patch("scanner.engine.create_scanner_client")
@patch("scanner.engine.discover_endpoints")
def test_engine_detects_legacy_api(
    mock_discover_endpoints,
    mock_client,
):

    endpoint = Endpoint(
        url="https://api.example.com/legacy/users",
        method="GET",
        path="/legacy/users",
        requires_auth=False,
    )

    mock_discover_endpoints.return_value = DiscoveryResult(
        endpoints=[endpoint],
        source="OpenAPI",
        specification_url="https://api.example.com/openapi.json",
    )

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.text = ""

    mock_client_instance = Mock()
    mock_client_instance.request.return_value = mock_response
    mock_client_instance.get.return_value = mock_response
    mock_client_instance.options.return_value = mock_response

    mock_client.return_value = mock_client_instance

    result = scan(
        url="https://api.example.com",
        mode=ScanMode.PASSIVE,
    )

    titles = [finding.title for finding in result.findings]

    assert "Potential Deprecated API Endpoint" in titles


@patch("scanner.engine.create_scanner_client")
@patch("scanner.engine.discover_endpoints")
def test_engine_detects_token_exposure(
    mock_discover_endpoints,
    mock_client,
):

    endpoint = Endpoint(
        url="https://api.example.com/token-test",
        method="GET",
        path="/token-test",
        requires_auth=False,
    )

    mock_discover_endpoints.return_value = DiscoveryResult(
        endpoints=[endpoint],
        source="OpenAPI",
        specification_url="https://api.example.com/openapi.json",
    )

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.text = (
        '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjN9.abc123signature", '
        '"api_key": "abcdefghijklmnop123456"}'
    )

    mock_client_instance = Mock()
    mock_client_instance.request.return_value = mock_response
    mock_client_instance.get.return_value = mock_response
    mock_client_instance.options.return_value = mock_response

    mock_client.return_value = mock_client_instance

    result = scan(
        url="https://api.example.com",
        mode=ScanMode.PASSIVE,
    )

    titles = [finding.title for finding in result.findings]

    assert "JWT Token Exposed in Response" in titles
    assert "Potential API Key Exposed in Response" in titles


@patch("scanner.engine.create_scanner_client")
@patch("scanner.engine.discover_endpoints")
def test_engine_passes_authorization_header(
    mock_discover_endpoints,
    mock_client,
):
    mock_discover_endpoints.return_value = DiscoveryResult(
        endpoints=[],
        source="OpenAPI",
    )

    mock_client_instance = Mock()
    mock_client.return_value = mock_client_instance

    scan(
        url="https://api.example.com",
        mode=ScanMode.PASSIVE,
        token="test_token_123",
    )

    mock_client.assert_called_once()
    kwargs = mock_client.call_args.kwargs
    assert kwargs["headers"] == {"Authorization": "Bearer test_token_123"}
    assert isinstance(kwargs["scan_deadline"], float)


@patch("scanner.engine.create_scanner_client")
@patch("scanner.engine.discover_endpoints")
def test_engine_marks_operator_interruption_as_interrupted(
    mock_discover_endpoints,
    mock_client,
):
    mock_discover_endpoints.return_value = DiscoveryResult(
        endpoints=[Endpoint(url="https://api.example.com/health", method="GET", path="/health")],
        source="OpenAPI",
    )
    client = Mock()
    client.request.side_effect = KeyboardInterrupt
    mock_client.return_value = client

    result = scan("https://api.example.com")

    assert result.scan_status == "interrupted"
    assert any("interrupted by operator" in error for error in result.errors)


@patch("scanner.engine.create_scanner_client")
@patch("scanner.engine.discover_endpoints", side_effect=KeyboardInterrupt)
def test_engine_marks_discovery_interruption_as_interrupted(mock_discover_endpoints, mock_client):
    client = Mock()
    mock_client.return_value = client

    result = scan("https://api.example.com")

    assert result.scan_status == "interrupted"
    assert result.endpoints_scanned == 0
    assert any("during endpoint discovery" in error for error in result.errors)
