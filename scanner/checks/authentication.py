from scanner.models import (
    Endpoint,
    Finding,
    Severity,
)


SENSITIVE_KEYWORDS = {
    "user",
    "users",
    "admin",
    "account",
    "accounts",
    "profile",
    "profiles",
    "order",
    "orders",
    "payment",
    "payments",
    "transaction",
    "transactions",
}


def check_missing_authentication(
    endpoint: Endpoint,
) -> list[Finding]:
    """
    Detect potentially sensitive endpoints
    that do not declare authentication.
    """

    path_lower = endpoint.path.lower()

    is_sensitive = any(
        keyword in path_lower
        for keyword in SENSITIVE_KEYWORDS
    )

    if is_sensitive and not endpoint.requires_auth:

        return [
            Finding(
                title="Potential Missing Authentication",
                severity=Severity.HIGH,
                description=(
                    "A potentially sensitive API endpoint "
                    "does not declare authentication requirements."
                ),
                endpoint=endpoint.url,
                recommendation=(
                    "Require appropriate authentication and "
                    "authorization before allowing access."
                ),
            )
        ]

    return []