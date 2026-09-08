from scanner.models import Finding, Severity


ERROR_PATTERNS = {
    "traceback": "Python traceback information exposed",
    "stack trace": "Stack trace information exposed",
}


FRAMEWORK_PATTERNS = [
    "django",
    "werkzeug",
    "fastapi",
]


def check_information_disclosure(
    endpoint: str,
    response,
) -> list[Finding]:
    """Check API responses for potential information disclosure."""

    findings = []

    response_text = response.text.lower()

    # Detect detailed error information
    for pattern, title in ERROR_PATTERNS.items():

        if pattern in response_text:

            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=title,
                    endpoint=endpoint,
                    description=(
                        "The API response may expose internal "
                        "error or implementation details."
                    ),
                    recommendation=(
                        "Disable detailed error messages and avoid "
                        "exposing stack traces in production."
                    ),
                    owasp="Security Misconfiguration",
                )
            )

            # Only report one detailed error finding
            break

    # Detect framework information
    for framework in FRAMEWORK_PATTERNS:

        if framework in response_text:

            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="Framework Information Exposed",
                    endpoint=endpoint,
                    description=(
                        "The API response may expose information "
                        "about the underlying framework."
                    ),
                    recommendation=(
                        "Disable debug information and minimize "
                        "technology disclosure in production."
                    ),
                    owasp="Security Misconfiguration",
                )
            )

            break

    # Detect server technology disclosure
    server_header = response.headers.get("server")

    if server_header:

        findings.append(
            Finding(
                severity=Severity.LOW,
                title="Server Technology Information Exposed",
                endpoint=endpoint,
                description=(
                    "The Server response header exposes information "
                    "about the web server technology."
                ),
                recommendation=(
                    "Remove or minimize server technology information "
                    "from HTTP response headers."
                ),
                owasp="Security Misconfiguration",
            )
        )

    return findings