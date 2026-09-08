import httpx

from scanner.models import Finding, Severity


MAX_TEST_REQUESTS = 5


def check_active_rate_limiting(
    client: httpx.Client,
    endpoint: str,
) -> list[Finding]:
    """
    Perform a small controlled request burst to check
    whether the endpoint appears to enforce rate limiting.
    """

    for _ in range(MAX_TEST_REQUESTS):

        try:
            response = client.get(endpoint)

        except httpx.RequestError:
            return []

        if response.status_code == 429:
            return []

    return [
        Finding(
            title="Rate Limiting Not Verified",
            severity=Severity.MEDIUM,
            description=(
                "The endpoint did not return HTTP 429 "
                "during a small controlled rate-limit test."
            ),
            endpoint=endpoint,
            recommendation=(
                "Implement and verify appropriate rate limiting "
                "for sensitive API endpoints."
            ),
        )
    ]