import re

import httpx

from scanner.models import Finding, Severity


SENSITIVE_PATTERNS = {
    "Potential Password Exposure": [
        r'"password"\s*:',
        r'"passwd"\s*:',
        r'"secret"\s*:',
    ],
    "Potential API Key Exposure": [
        r'"api[_-]?key"\s*:',
        r'"access[_-]?key"\s*:',
    ],
    "Potential JWT Exposure": [
        r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    ],
    "Potential Private Key Exposure": [
        r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    ],
    "Potential Debug Information Exposure": [
        r"Traceback \(most recent call last\)",
        r"File \".+\", line \d+",
        r"sqlalchemy\.",
        r"psycopg2\.",
    ],
}


def check_sensitive_data(
    endpoint: str,
    response: httpx.Response,
) -> list[Finding]:
    """Check an API response for potentially sensitive information."""

    findings = []

    try:
        body = response.text
    except Exception:
        return []

    for title, patterns in SENSITIVE_PATTERNS.items():

        for pattern in patterns:

            if re.search(
                pattern,
                body,
                re.IGNORECASE,
            ):

                severity = (
                    Severity.HIGH
                    if "Private Key" in title
                    or "Password" in title
                    else Severity.MEDIUM
                )

                findings.append(
                    Finding(
                        title=title,
                        severity=severity,
                        description=(
                            "The API response contains content "
                            "that may expose sensitive information."
                        ),
                        endpoint=endpoint,
                        recommendation=(
                            "Remove sensitive data and debug "
                            "information from API responses."
                        ),
                    )
                )

                break

    return findings