import httpx

from scanner.models import Finding, Severity


SECURITY_HEADERS = {
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing.",
        "recommendation": "Add the X-Content-Type-Options: nosniff header.",
    },
    "X-Frame-Options": {
        "description": "Helps protect against clickjacking attacks.",
        "recommendation": "Add the X-Frame-Options header.",
    },
}


def check_security_headers(
    url: str,
    response: httpx.Response,
) -> list[Finding]:

    findings = []

    for header, info in SECURITY_HEADERS.items():

        if header.lower() not in {
            key.lower() for key in response.headers.keys()
        }:

            findings.append(
                Finding(
                    title=f"Missing {header} Header",
                    severity=Severity.LOW,
                    description=info["description"],
                    endpoint=url,
                    recommendation=info["recommendation"],
                )
            )

    return findings