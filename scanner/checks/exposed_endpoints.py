"""OWASP API5:2023 - Broken Function Level Authorization (BFLA) Check."""

from scanner.models import Endpoint, Finding, Severity

SENSITIVE_PATHS = {
    "/admin": {
        "title": "Exposed Administrative Endpoint",
        "description": "An administrative endpoint appears to be publicly accessible without expected authorization barriers.",
        "recommendation": "Restrict administrative endpoints using strict role-based access control (RBAC) and mutual TLS / VPN restrictions.",
        "severity": Severity.HIGH,
    },
    "/manage": {
        "title": "Exposed Management Endpoint",
        "description": "A management endpoint appears to be publicly accessible.",
        "recommendation": "Restrict management endpoints to authorized administrators with MFA.",
        "severity": Severity.HIGH,
    },
    "/internal": {
        "title": "Exposed Internal Endpoint",
        "description": "An internal service route appears to be exposed on the public interface.",
        "recommendation": "Keep internal microservice endpoints isolated within private VPC subnets.",
        "severity": Severity.HIGH,
    },
    "/debug": {
        "title": "Exposed Debug Endpoint",
        "description": "A debug interface appears to be publicly accessible.",
        "recommendation": "Disable debug endpoints in production environments.",
        "severity": Severity.MEDIUM,
    },
    "/metrics": {
        "title": "Exposed Metrics Endpoint",
        "description": "System or application performance metrics appear to be publicly accessible.",
        "recommendation": "Restrict access to internal telemetry and Prometheus/OpenTelemetry metrics endpoints.",
        "severity": Severity.MEDIUM,
    },
    "/actuator": {
        "title": "Exposed Management Endpoint",
        "description": "Spring Boot / framework actuator management endpoint appears to be exposed.",
        "recommendation": "Disable or protect actuator endpoints to prevent runtime introspection.",
        "severity": Severity.HIGH,
    },
}


def check_exposed_endpoint(
    endpoint: str | Endpoint,
    status_code: int,
) -> list[Finding]:
    """Check whether a sensitive or privileged endpoint is publicly accessible (BFLA risk)."""
    if isinstance(endpoint, Endpoint):
        endpoint_url = endpoint.url
        path_lower = endpoint.path.lower()
    else:
        endpoint_url = str(endpoint)
        path_lower = str(endpoint).lower()

    findings: list[Finding] = []

    for path, details in SENSITIVE_PATHS.items():
        if path_lower.rstrip("/").endswith(path) or f"{path}/" in path_lower:
            if 200 <= status_code < 400:
                findings.append(
                    Finding(
                        severity=details["severity"],
                        title=details["title"],
                        endpoint=endpoint_url,
                        owasp="API5:2023 - Broken Function Level Authorization",
                        description=details["description"],
                        recommendation=details["recommendation"],
                    )
                )
                break

    return findings