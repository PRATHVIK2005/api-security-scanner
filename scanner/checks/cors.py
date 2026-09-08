import httpx

from scanner.models import Finding, Severity


TEST_ORIGIN = "https://scanner-test.example"


def analyze_cors_response(
    endpoint: str,
    response: httpx.Response,
) -> list[Finding]:
    """Analyze an HTTP response for CORS misconfigurations."""

    findings = []

    allow_origin = response.headers.get(
        "access-control-allow-origin"
    )

    allow_credentials = response.headers.get(
        "access-control-allow-credentials"
    )

    if allow_origin == "*":

        severity = (
            Severity.HIGH
            if allow_credentials
            and allow_credentials.lower() == "true"
            else Severity.MEDIUM
        )

        findings.append(
            Finding(
                title="Overly Permissive CORS Policy",
                severity=severity,
                description=(
                    "The API allows cross-origin requests "
                    "from any origin."
                ),
                endpoint=endpoint,
                recommendation=(
                    "Restrict Access-Control-Allow-Origin "
                    "to explicitly trusted origins."
                ),
            )
        )

    return findings


def check_cors(
    client: httpx.Client,
    endpoint: str,
) -> list[Finding]:
    """Send a safe CORS probe and analyze the response."""

    try:
        response = client.get(
            endpoint,
            headers={
                "Origin": TEST_ORIGIN,
            },
        )

    except httpx.RequestError:
        return []

    return analyze_cors_response(
        endpoint,
        response,
    )