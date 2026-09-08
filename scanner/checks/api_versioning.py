"""OWASP API9:2023 - Improper Inventory Management Check."""

from scanner.models import Endpoint, Finding, Severity

LEGACY_KEYWORDS = {
    "legacy",
    "deprecated",
    "old",
    "archive",
}


def check_api_versioning(
    endpoint: Endpoint | str,
    method: str = "GET",
) -> list[Finding]:
    """Detect potentially outdated or deprecated API endpoints (Improper Inventory Management)."""
    if isinstance(endpoint, Endpoint):
        endpoint_url = endpoint.url
        path_lower = endpoint.path.lower()
        method = endpoint.method
        is_deprecated_spec = bool(endpoint.deprecated)
    else:
        endpoint_url = str(endpoint)
        path_lower = str(endpoint).lower()
        is_deprecated_spec = False

    findings: list[Finding] = []

    # 1. Check OpenAPI specification explicit deprecation flag
    if is_deprecated_spec:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Deprecated OpenAPI Operation Declared",
                endpoint=endpoint_url,
                method=method,
                owasp="API9:2023 - Improper Inventory Management",
                description=(
                    "The OpenAPI contract explicitly marks this operation as deprecated. "
                    "Running deprecated endpoints increases attack surface and security debt if unmaintained."
                ),
                recommendation=(
                    "Sunset deprecated endpoints according to an API deprecation schedule and redirect clients to current versioned endpoints."
                ),
            )
        )
    # 2. Detect potentially deprecated endpoint path naming
    elif any(keyword in path_lower for keyword in LEGACY_KEYWORDS):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Potential Deprecated API Endpoint",
                endpoint=endpoint_url,
                method=method,
                owasp="API9:2023 - Improper Inventory Management",
                description=(
                    "The endpoint route structure contains legacy or deprecated naming conventions."
                ),
                recommendation=(
                    "Review whether this legacy endpoint is still required and remove or restrict access to retired API routes."
                ),
            )
        )

    # 3. Detect early / pre-release / unmaintained API version prefixes
    if (
        "/v0/" in path_lower
        or "/v1beta" in path_lower
        or "/v1alpha" in path_lower
        or "/v0." in path_lower
    ):
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="Potential Outdated API Version",
                endpoint=endpoint_url,
                method=method,
                owasp="API9:2023 - Improper Inventory Management",
                description=(
                    "The endpoint appears to use an early, preview, or pre-release API version prefix."
                ),
                recommendation=(
                    "Maintain an accurate API catalog and migrate traffic from beta/alpha endpoints to stable GA releases."
                ),
            )
        )

    return findings