import httpx

from scanner.checks.active_rate_limiting import (
    check_active_rate_limiting,
)


def test_rate_limiting_detected():

    class MockClient:

        def get(self, endpoint):
            return httpx.Response(
                429
            )

    findings = check_active_rate_limiting(
        MockClient(),
        "https://api.example.com/users",
    )

    assert findings == []


def test_rate_limiting_not_detected():

    class MockClient:

        def get(self, endpoint):
            return httpx.Response(
                200
            )

    findings = check_active_rate_limiting(
        MockClient(),
        "https://api.example.com/users",
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"