import httpx

from scanner.checks.misconfiguration import check_security_headers


def test_missing_security_headers():
    request = httpx.Request("GET", "https://example.com")

    response = httpx.Response(
        200,
        request=request,
        headers={},
    )

    findings = check_security_headers(
        "https://example.com",
        response,
    )

    assert len(findings) == 2


def test_security_headers_present():
    request = httpx.Request("GET", "https://example.com")

    response = httpx.Response(
        200,
        request=request,
        headers={
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )

    findings = check_security_headers(
        "https://example.com",
        response,
    )

    assert len(findings) == 0