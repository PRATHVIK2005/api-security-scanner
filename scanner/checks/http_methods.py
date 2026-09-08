import httpx

from scanner.models import Finding, Severity


DANGEROUS_METHODS = {
    "TRACE": {
        "severity": Severity.MEDIUM,
        "title": "Dangerous TRACE Method Enabled",
        "description": (
            "The API supports the TRACE HTTP method, which may expose "
            "request information and increase security risks."
        ),
        "recommendation": (
            "Disable the TRACE HTTP method unless it is explicitly "
            "required."
        ),
    },
    "CONNECT": {
        "severity": Severity.MEDIUM,
        "title": "Dangerous CONNECT Method Enabled",
        "description": (
            "The API supports the CONNECT HTTP method, which may allow "
            "unexpected proxy or tunneling behavior."
        ),
        "recommendation": (
            "Disable the CONNECT HTTP method unless it is explicitly "
            "required."
        ),
    },
}


def check_http_methods(
    client: httpx.Client,
    endpoint: str,
) -> list[Finding]:
    """Check an endpoint for potentially dangerous HTTP methods."""

    findings = []

    try:
        response = client.options(endpoint)

    except httpx.RequestError:
        return findings

    allowed_methods = response.headers.get(
        "allow",
        "",
    )

    methods = {
        method.strip().upper()
        for method in allowed_methods.split(",")
        if method.strip()
    }

    for method in DANGEROUS_METHODS:

        if method in methods:

            issue = DANGEROUS_METHODS[method]

            findings.append(
                Finding(
                    severity=issue["severity"],
                    title=issue["title"],
                    endpoint=endpoint,
                    description=issue["description"],
                    recommendation=issue["recommendation"],
                    owasp="Security Misconfiguration",
                )
            )

    return findings