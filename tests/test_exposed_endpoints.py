from scanner.checks.exposed_endpoints import (
    check_exposed_endpoint,
)
from scanner.models import Severity


def test_exposed_admin_endpoint():

    findings = check_exposed_endpoint(
        "https://api.example.com/admin",
        200,
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].title == (
        "Exposed Administrative Endpoint"
    )


def test_exposed_debug_endpoint():

    findings = check_exposed_endpoint(
        "https://api.example.com/debug",
        200,
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_unavailable_sensitive_endpoint():

    findings = check_exposed_endpoint(
        "https://api.example.com/admin",
        404,
    )

    assert findings == []


def test_normal_endpoint():

    findings = check_exposed_endpoint(
        "https://api.example.com/users",
        200,
    )

    assert findings == []