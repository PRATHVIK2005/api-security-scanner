import httpx

from scanner.checks.token_security import (
    check_token_security,
)
from scanner.models import Severity


def make_response(
    content: str,
) -> httpx.Response:

    return httpx.Response(
        status_code=200,
        text=content,
    )


def test_detects_exposed_jwt():

    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJ1c2VyX2lkIjoxMjN9."
        "abc123signature"
    )

    response = make_response(
        f'{{"token": "{token}"}}'
    )

    findings = check_token_security(
        "https://api.example.com/users",
        response,
    )

    assert len(findings) == 1

    assert (
        findings[0].title
        == "JWT Token Exposed in Response"
    )

    assert findings[0].severity == Severity.HIGH


def test_detects_api_key():

    response = make_response(
        '{"api_key": "abcdefghijklmnop123456"}'
    )

    findings = check_token_security(
        "https://api.example.com/config",
        response,
    )

    assert len(findings) == 1

    assert (
        findings[0].title
        == "Potential API Key Exposed in Response"
    )

    assert findings[0].severity == Severity.HIGH


def test_detects_secret_key():

    response = make_response(
        '{"secret_key": "abcdefghijklmnop123456"}'
    )

    findings = check_token_security(
        "https://api.example.com/config",
        response,
    )

    assert len(findings) == 1

    assert (
        findings[0].title
        == "Potential API Key Exposed in Response"
    )


def test_normal_response_has_no_findings():

    response = make_response(
        '{"message": "Request completed successfully"}'
    )

    findings = check_token_security(
        "https://api.example.com/users",
        response,
    )

    assert findings == []


def test_invalid_response_returns_no_error():

    class BrokenResponse:

        @property
        def text(self):
            raise ValueError("Cannot read response")

    findings = check_token_security(
        "https://api.example.com/test",
        BrokenResponse(),
    )

    assert findings == []
