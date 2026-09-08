import re

from scanner.models import Finding, Severity


JWT_PATTERN = re.compile(
    r"eyJ[a-zA-Z0-9_-]+\."
    r"[a-zA-Z0-9_-]+\."
    r"[a-zA-Z0-9_-]+"
)


API_KEY_PATTERNS = [
    re.compile(
        r'(?i)(api[_-]?key|apikey)'
        r'["\']?\s*[:=]\s*["\']'
        r'[a-zA-Z0-9_\-]{16,}'
    ),
    re.compile(
        r'(?i)(secret[_-]?key|access[_-]?key)'
        r'["\']?\s*[:=]\s*["\']'
        r'[a-zA-Z0-9_\-]{16,}'
    ),
]


def check_token_security(
    endpoint: str,
    response,
) -> list[Finding]:
    """Check HTTP responses for exposed JWTs and API keys."""

    findings = []

    try:
        response_text = response.text
    except Exception:
        return findings

    # Detect JWT tokens
    if JWT_PATTERN.search(response_text):

        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="JWT Token Exposed in Response",
                endpoint=endpoint,
            )
        )

    # Detect potential API keys
    for pattern in API_KEY_PATTERNS:

        if pattern.search(response_text):

            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Potential API Key Exposed in Response",
                    endpoint=endpoint,
                )
            )

            break

    return findings
