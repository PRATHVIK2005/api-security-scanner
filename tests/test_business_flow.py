from scanner.checks.business_flow import check_business_flow
from scanner.models import Endpoint


def test_detects_sensitive_business_flows():
    endpoints = [
        Endpoint(url="https://api.example.com/api/v1/checkout", method="POST", path="/api/v1/checkout"),
        Endpoint(url="https://api.example.com/auth/login", method="POST", path="/auth/login"),
        Endpoint(url="https://api.example.com/auth/password_reset", method="POST", path="/auth/password_reset"),
        Endpoint(url="https://api.example.com/promotions/redeem-coupon", method="POST", path="/promotions/redeem-coupon"),
    ]

    for ep in endpoints:
        findings = check_business_flow(ep)
        assert len(findings) == 1
        assert findings[0].title == "Potential Unrestricted Sensitive Business Flow"
        assert "API6:2023" in findings[0].owasp


def test_detects_business_flow_from_metadata():
    endpoint = Endpoint(
        url="https://api.example.com/submit",
        method="POST",
        path="/submit",
        summary="User Authentication Flow",
        tags=["auth", "login"],
    )
    findings = check_business_flow(endpoint)
    assert len(findings) == 1
    assert findings[0].title == "Potential Unrestricted Sensitive Business Flow"


def test_non_sensitive_endpoint_has_no_business_flow_finding():
    endpoint = Endpoint(
        url="https://api.example.com/products/search",
        method="GET",
        path="/products/search",
        summary="Search product catalog",
    )
    findings = check_business_flow(endpoint)
    assert findings == []
