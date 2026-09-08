from scanner.checks.unsafe_api_consumption import check_unsafe_api_consumption
from scanner.models import Endpoint


def test_detects_webhook_endpoint():
    endpoint = Endpoint(
        url="https://api.example.com/api/v1/stripe/webhook",
        method="POST",
        path="/api/v1/stripe/webhook",
    )
    findings = check_unsafe_api_consumption(endpoint)
    assert len(findings) == 1
    assert findings[0].title == "Potential Unsafe External API Consumption"
    assert "API10:2023" in findings[0].owasp


def test_detects_proxy_or_third_party_from_metadata():
    endpoint = Endpoint(
        url="https://api.example.com/data/partner",
        method="GET",
        path="/data/partner",
        summary="Third-party service synchronization bridge",
    )
    findings = check_unsafe_api_consumption(endpoint)
    assert len(findings) == 1
    assert findings[0].title == "Potential Unsafe External API Consumption"


def test_internal_normal_endpoint_has_no_unsafe_consumption_finding():
    endpoint = Endpoint(
        url="https://api.example.com/users/me",
        method="GET",
        path="/users/me",
        summary="Retrieve user profile",
    )
    findings = check_unsafe_api_consumption(endpoint)
    assert findings == []
