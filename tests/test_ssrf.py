from scanner.checks.ssrf import check_ssrf
from scanner.models import Endpoint


def test_detects_ssrf_query_parameters():
    endpoint = Endpoint(
        url="https://api.example.com/fetch",
        method="GET",
        path="/fetch",
        parameters=[
            {"name": "target_url", "in": "query"},
            {"name": "format", "in": "query"},
        ],
    )
    findings = check_ssrf(endpoint)
    assert len(findings) == 1
    assert findings[0].title == "Potential SSRF Input Risk"
    assert "target_url" in findings[0].description


def test_detects_ssrf_request_body_schema():
    endpoint = Endpoint(
        url="https://api.example.com/webhooks/register",
        method="POST",
        path="/webhooks/register",
        request_body_schema={
            "type": "object",
            "properties": {
                "callback_url": {"type": "string"},
                "events": {"type": "array"},
            },
        },
    )
    findings = check_ssrf(endpoint)
    assert len(findings) == 1
    assert findings[0].title == "Potential SSRF Input Risk"
    assert "callback_url" in findings[0].description


def test_clean_endpoint_has_no_ssrf_finding():
    endpoint = Endpoint(
        url="https://api.example.com/users",
        method="GET",
        path="/users",
        parameters=[{"name": "limit", "in": "query"}, {"name": "offset", "in": "query"}],
    )
    findings = check_ssrf(endpoint)
    assert findings == []
