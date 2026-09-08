import httpx

from scanner.checks.rate_limiting import (
    check_rate_limiting,
)


def test_missing_rate_limit_headers():

    response = httpx.Response(
        200,
        headers={},
    )

    findings = check_rate_limiting(
        "https://api.example.com/users",
        response,
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"


def test_standard_rate_limit_headers():

    response = httpx.Response(
        200,
        headers={
            "RateLimit-Limit": "100",
            "RateLimit-Remaining": "99",
            "RateLimit-Reset": "60",
        },
    )

    findings = check_rate_limiting(
        "https://api.example.com/users",
        response,
    )

    assert findings == []


def test_x_rate_limit_headers():

    response = httpx.Response(
        200,
        headers={
            "X-RateLimit-Limit": "100",
            "X-RateLimit-Remaining": "99",
        },
    )

    findings = check_rate_limiting(
        "https://api.example.com/users",
        response,
    )

    assert findings == []