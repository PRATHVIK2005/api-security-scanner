from scanner.checks.authentication import (
    check_missing_authentication,
)
from scanner.models import Endpoint


def test_sensitive_endpoint_without_authentication():

    endpoint = Endpoint(
        url="https://api.example.com/users",
        method="GET",
        path="/users",
        requires_auth=False,
    )

    findings = check_missing_authentication(endpoint)

    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"


def test_sensitive_endpoint_with_authentication():

    endpoint = Endpoint(
        url="https://api.example.com/users",
        method="GET",
        path="/users",
        requires_auth=True,
    )

    findings = check_missing_authentication(endpoint)

    assert findings == []


def test_public_endpoint_without_authentication():

    endpoint = Endpoint(
        url="https://api.example.com/health",
        method="GET",
        path="/health",
        requires_auth=False,
    )

    findings = check_missing_authentication(endpoint)

    assert findings == []