import json
from unittest.mock import Mock, patch

import httpx
import pytest

from scanner.discovery import discover_endpoints, load_endpoint_list, parse_openapi
from scanner.engine import scan
from scanner.models import DiscoveryResult, Endpoint, Finding, ScanMode, ScanResult, Severity
from scanner.reports.html_report import generate_html_report
from scanner.reports.pdf_report import generate_pdf_report
from scanner.deduplication import deduplicate_findings
from scanner.validation import InvalidURLError, validate_target_url


@pytest.mark.parametrize(
    "url",
    [
        "http://user:pass@example.com",
        "http://example.com:99999",
        "http://example.com:",
        "https://bad..host/path",
        "http://example.com/path with spaces",
        "http://example.com:abc",
    ],
)
def test_target_url_rejects_credentials_malformed_host_and_port(url):
    with pytest.raises(InvalidURLError):
        validate_target_url(url)


def test_target_url_normalizes_trailing_slash_and_allows_loopback():
    assert validate_target_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"


def test_openapi_preserves_methods_and_operation_metadata():
    endpoints = parse_openapi(
        {
            "security": [{"bearer": []}],
            "paths": {
                "/users/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                    "get": {
                        "operationId": "readUser",
                        "tags": ["users"],
                        "deprecated": True,
                        "responses": {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}},
                    },
                    "post": {
                        "security": [],
                        "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                    },
                    "parameters_extra": {},
                }
            },
        },
        "https://api.example.test/v1",
    )
    assert [(e.method, e.path) for e in endpoints] == [("GET", "/users/{id}"), ("POST", "/users/{id}")]
    assert endpoints[0].requires_auth and endpoints[0].deprecated
    assert endpoints[0].parameters[0]["name"] == "id"
    assert endpoints[0].response_schemas == {"200": {"type": "object"}}
    assert endpoints[1].requires_auth is False
    assert endpoints[1].request_body_schema == {"type": "object"}


def test_discovery_falls_through_404_and_records_probe_outcome():
    response = httpx.Response(404, request=httpx.Request("GET", "https://api.example.test/openapi.json"))
    fake_client = Mock()
    fake_client.get.return_value = response
    manager = Mock()
    manager.__enter__ = Mock(return_value=fake_client)
    manager.__exit__ = Mock(return_value=False)
    with patch("scanner.discovery.create_scanner_client", return_value=manager):
        result = discover_endpoints("https://api.example.test")
    assert fake_client.get.call_count == 6
    assert result.source == "Fallback"
    assert len(result.endpoints) == 1
    assert result.attempts[0].endswith("HTTP 404")
    assert result.limitations


def test_discovery_does_not_follow_spec_redirect():
    response = httpx.Response(
        302,
        headers={"location": "http://169.254.169.254/"},
        request=httpx.Request("GET", "https://api.example.test/openapi.json"),
    )
    fake_client = Mock()
    fake_client.get.return_value = response
    manager = Mock()
    manager.__enter__ = Mock(return_value=fake_client)
    manager.__exit__ = Mock(return_value=False)
    with patch("scanner.discovery.create_scanner_client", return_value=manager):
        result = discover_endpoints(
            "https://api.example.test", specification_url="https://api.example.test/openapi.json"
        )
    fake_client.get.assert_called_once()
    assert result.source == "Fallback"
    assert "redirect not followed" in result.attempts[0]


def test_manual_endpoint_list_deduplicates_method_path_and_rejects_bad_methods(tmp_path):
    source = tmp_path / "endpoints.json"
    source.write_text(
        json.dumps(
            {
                "endpoints": [
                    {"method": "get", "path": "/users", "summary": "List"},
                    {"method": "GET", "path": "users"},
                    {"method": "POST", "path": "/users"},
                ]
            }
        ),
        encoding="utf-8",
    )
    found = load_endpoint_list(source, "https://api.example.test/v1")
    assert [(e.method, e.url) for e in found] == [
        ("GET", "https://api.example.test/v1/users"),
        ("POST", "https://api.example.test/v1/users"),
    ]
    source.write_text('[{"method":"TRACE","path":"/users"}]', encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported method"):
        load_endpoint_list(source, "https://api.example.test")


def test_manual_endpoint_list_rejects_out_of_scope_url(tmp_path):
    source = tmp_path / "endpoints.json"
    source.write_text('[{"method":"GET","path":"https://elsewhere.test/private"}]', encoding="utf-8")
    with pytest.raises(ValueError, match="outside the target origin"):
        load_endpoint_list(source, "https://api.example.test")


def test_manual_yaml_endpoint_list(tmp_path):
    source = tmp_path / "endpoints.yaml"
    source.write_text("endpoints:\n  - method: GET\n    path: /health\n    summary: Health\n", encoding="utf-8")
    found = load_endpoint_list(source, "https://api.example.test")
    assert found[0].method == "GET" and found[0].path == "/health"


@pytest.mark.parametrize(
    "document, expected", [(b"not: [valid", "malformed"), (b'{"paths": {}}', "no usable operations")]
)
def test_specification_failure_categories_are_reported(document, expected):
    response = httpx.Response(200, content=document, request=httpx.Request("GET", "https://api.example.test/spec"))
    fake_client = Mock()
    fake_client.get.return_value = response
    manager = Mock()
    manager.__enter__ = Mock(return_value=fake_client)
    manager.__exit__ = Mock(return_value=False)
    with patch("scanner.discovery.create_scanner_client", return_value=manager):
        result = discover_endpoints("https://api.example.test", specification_url="https://api.example.test/spec")
    assert expected in result.attempts[0]


def test_explicit_spec_outside_target_origin_is_refused():
    fake_client = Mock()
    manager = Mock()
    manager.__enter__ = Mock(return_value=fake_client)
    manager.__exit__ = Mock(return_value=False)
    with patch("scanner.discovery.create_scanner_client", return_value=manager):
        result = discover_endpoints("https://api.example.test", specification_url="https://other.example/spec")
    fake_client.get.assert_not_called()
    assert "outside target origin" in result.attempts[0]


def test_external_openapi_refs_are_reported_but_never_fetched():
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/objects": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {"application/json": {"schema": {"$ref": "https://other.example/schema.json"}}}
                        }
                    }
                }
            }
        },
    }
    response = httpx.Response(
        200,
        json=document,
        request=httpx.Request("GET", "https://api.example.test/openapi.json"),
    )
    client = Mock()
    client.get.return_value = response
    result = discover_endpoints(
        "https://api.example.test",
        specification_url="https://api.example.test/openapi.json",
        client=client,
    )
    client.get.assert_called_once()
    assert result.endpoints
    assert any("external reference(s) were not fetched" in item for item in result.limitations)


def test_json_and_yaml_nesting_and_aliases_are_bounded(tmp_path):
    from scanner.discovery import _load_document

    deep = b'{"x":' * 102 + b"0" + b"}" * 102
    with pytest.raises(ValueError, match="depth limit"):
        _load_document(deep)
    alias_file = tmp_path / "aliased.yaml"
    alias_file.write_text("endpoints: &items\n  - path: /health\ncopy: *items\n", encoding="utf-8")
    with pytest.raises(ValueError, match="aliases are not supported"):
        load_endpoint_list(alias_file, "https://api.example.test")


def test_active_scan_never_sends_write_operations():
    endpoints = [
        Endpoint(url="http://127.0.0.1:8000/write", method="POST", path="/write"),
        Endpoint(url="http://127.0.0.1:8000/read", method="GET", path="/read"),
    ]
    response = Mock(status_code=200, headers={}, text="{}")
    client = Mock()
    client.request.return_value = response
    client.get.return_value = response
    client.options.return_value = response
    with (
        patch("scanner.engine.discover_endpoints", return_value=DiscoveryResult(endpoints=endpoints, source="test")),
        patch("scanner.engine.create_scanner_client", return_value=client),
    ):
        result = scan("http://127.0.0.1:8000", mode=ScanMode.ACTIVE)
    assert result.endpoints_scanned == 1
    assert {call.args[0] for call in client.request.call_args_list} == {"GET"}


def test_html_report_escapes_untrusted_finding_content():
    result = ScanResult(
        target="https://api.example.test",
        endpoints_scanned=1,
        findings=[
            Finding(
                severity=Severity.LOW,
                title="<script>alert(1)</script>",
                endpoint="https://api.example.test/?x=<svg>",
                description="<img src=x onerror=alert(1)>",
                evidence="<script>evidence</script>",
            )
        ],
        scan_status="partial",
        errors=["<img src=x onerror=alert(1)>"],
    )
    report = generate_html_report(result)
    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;" in report
    assert "&lt;img" in report
    assert "<script>evidence</script>" not in report
    assert "&lt;script&gt;evidence" in report
    assert "Scan Status" in report and "partial" in report
    assert "&lt;img src=x" in report


def test_pdf_report_escapes_untrusted_content_and_supports_unicode():
    result = ScanResult(
        target="https://api.example.test",
        endpoints_scanned=1,
        findings=[
            Finding(
                severity=Severity.LOW,
                title="Unicode ✓ <b>plain text</b>",
                endpoint="https://api.example.test/?value=✓",
                description="Long text & symbols: <unsafe> Ω",
            )
        ],
    )
    content = generate_pdf_report(result)
    assert content.startswith(b"%PDF-")
    assert len(content) > 100
    partial = ScanResult(
        target="https://api.example.test",
        endpoints_scanned=0,
        findings=[],
        scan_status="interrupted",
        errors=["Operator interruption <reported>"],
    )
    assert generate_pdf_report(partial).startswith(b"%PDF-")


def test_finding_redacts_secrets_and_deduplication_keeps_distinct_checks():
    first = Finding(
        severity=Severity.MEDIUM,
        title="Risk",
        endpoint="https://api.example.test/x?access_token=secret",
        check_id="check-a",
        evidence="Authorization: Bearer abc.def.ghi",
    )
    second = Finding(
        severity=Severity.MEDIUM,
        title="Risk",
        endpoint="https://api.example.test/x?access_token=secret",
        check_id="check-b",
    )
    unique = deduplicate_findings([first, second])
    assert len(unique) == 2
    assert "secret" not in first.endpoint
    assert "abc.def.ghi" not in first.evidence
    assert first.finding_id != second.finding_id


def test_redaction_removes_url_credentials_cookies_and_session_values():
    finding = Finding(
        severity=Severity.LOW,
        title="Cookie: sessionid=private",
        endpoint="https://user:password@api.example.test/x?session=private",
        evidence="Cookie: sessionid=private; auth=secret\nsessionid=private access_token=abc123\nAuthorization: Bearer abc.def.ghi",
    )
    serialized = finding.model_dump_json()
    for secret in ("user", "password", "sessionid=private", "abc123", "abc.def.ghi", "auth=secret"):
        assert secret not in serialized
