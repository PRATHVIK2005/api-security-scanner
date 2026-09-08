import httpx

from scanner.checks.cors import (
    analyze_cors_response,
)


def test_wildcard_cors():

    response = httpx.Response(
        200,
        headers={
            "Access-Control-Allow-Origin": "*",
        },
    )

    findings = analyze_cors_response(
        "https://api.example.com/users",
        response,
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"


def test_wildcard_cors_with_credentials():

    response = httpx.Response(
        200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )

    findings = analyze_cors_response(
        "https://api.example.com/users",
        response,
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"


def test_restricted_cors():

    response = httpx.Response(
        200,
        headers={
            "Access-Control-Allow-Origin":
                "https://trusted.example.com",
        },
    )

    findings = analyze_cors_response(
        "https://api.example.com/users",
        response,
    )

    assert findings == []