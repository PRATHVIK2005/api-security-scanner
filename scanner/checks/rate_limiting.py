from scanner.models import Finding, Severity


RATE_LIMIT_HEADERS = {
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
}


def check_rate_limiting(
    endpoint: str,
    response,
) -> list[Finding]:
    """Check whether the response exposes rate-limiting information."""

    response_headers = {
        header.lower()
        for header in response.headers.keys()
    }

    has_rate_limit_headers = bool(
        RATE_LIMIT_HEADERS.intersection(
            response_headers
        )
    )

    if not has_rate_limit_headers:
        return [
            Finding(
                title="Potential Missing Rate Limiting",
                severity=Severity.MEDIUM,
                description=(
                    "The API response does not expose common "
                    "rate-limiting headers. This may indicate that "
                    "rate limiting is not configured or is not visible "
                    "to clients."
                ),
                endpoint=endpoint,
                recommendation=(
                    "Implement rate limiting for API endpoints, "
                    "especially authentication and sensitive endpoints."
                ),
            )
        ]

    return []