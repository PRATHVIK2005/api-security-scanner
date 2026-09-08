import httpx

from scanner.checks.sensitive_data import (
    check_sensitive_data,
)


def test_password_exposure():

    response = httpx.Response(
        200,
        json={
            "username": "demo",
            "password": "super-secret-password",
        },
    )

    findings = check_sensitive_data(
        "https://api.example.com/users",
        response,
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"


def test_api_key_exposure():

    response = httpx.Response(
        200,
        json={
            "api_key": "example-secret-key",
        },
    )

    findings = check_sensitive_data(
        "https://api.example.com/config",
        response,
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"


def test_jwt_exposure():

    response = httpx.Response(
        200,
        text=(
            '{"token": '
            '"eyJhbGciOiJIUzI1NiJ9.'
            'eyJ1c2VyIjoxfQ.'
            'exampleSignature"}'
        ),
    )

    findings = check_sensitive_data(
        "https://api.example.com/profile",
        response,
    )

    assert len(findings) == 1


def test_debug_information_exposure():

    response = httpx.Response(
        500,
        text=(
            "Traceback (most recent call last):\n"
            'File "app.py", line 42'
        ),
    )

    findings = check_sensitive_data(
        "https://api.example.com/error",
        response,
    )

    assert len(findings) == 1
    assert findings[0].title == (
        "Potential Debug Information Exposure"
    )


def test_safe_response():

    response = httpx.Response(
        200,
        json={
            "message": "Success",
            "status": "healthy",
        },
    )

    findings = check_sensitive_data(
        "https://api.example.com/health",
        response,
    )

    assert findings == []