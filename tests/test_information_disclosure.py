import httpx

from scanner.checks.information_disclosure import (
    check_information_disclosure,
)
from scanner.models import Severity


def make_response(
    text: str = "",
    headers: dict | None = None,
) -> httpx.Response:

    return httpx.Response(
        status_code=200,
        text=text,
        headers=headers or {},
    )


def test_detects_python_traceback():

    response = make_response(
        text="Traceback (most recent call last)",
    )

    findings = check_information_disclosure(
        "https://api.example.com",
        response,
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].title == (
        "Python traceback information exposed"
    )


def test_detects_stack_trace():

    response = make_response(
        text="An error occurred. Stack trace follows.",
    )

    findings = check_information_disclosure(
        "https://api.example.com",
        response,
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_detects_server_header():

    response = make_response(
        headers={
            "server": "nginx/1.24",
        },
    )

    findings = check_information_disclosure(
        "https://api.example.com",
        response,
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].title == (
        "Server Technology Information Exposed"
    )


def test_no_disclosure_found():

    response = make_response(
        text="API response successful",
    )

    findings = check_information_disclosure(
        "https://api.example.com",
        response,
    )

    assert findings == []
    
def test_does_not_duplicate_error_findings():

    response = make_response(
        text=(
            "Traceback occurred. "
            "A stack trace is available."
        ),
    )

    findings = check_information_disclosure(
        "https://api.example.com",
        response,
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_detects_framework_information():

    response = make_response(
        text="Werkzeug development server",
    )

    findings = check_information_disclosure(
        "https://api.example.com",
        response,
    )

    assert len(findings) == 1
    assert findings[0].title == (
        "Framework Information Exposed"
    )