import re
from scanner.models import Endpoint, Finding, Severity


ID_PARAM_PATTERNS = [
    r"^id$",
    r"^.*_id$",
    r"^.*id$",
    r"^uuid$",
    r"^guid$",
    r"^key$",
    r"^account.*",
    r"^user.*",
    r"^order.*",
    r"^product.*",
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in ID_PARAM_PATTERNS]


def is_object_identifier_name(name: str) -> bool:
    """Check whether a parameter name represents an object reference identifier."""
    cleaned = name.strip().lower().replace("-", "_")
    return any(pattern.match(cleaned) for pattern in COMPILED_PATTERNS)


def check_bola_risk(
    endpoint: str | Endpoint,
    method: str = "GET",
    parameters: list[dict] | None = None,
) -> list[Finding]:
    """
    Detect endpoints containing object identifiers in paths or query parameters
    that may require object-level authorization validation (BOLA / IDOR risk indicator).
    """
    if isinstance(endpoint, Endpoint):
        path = endpoint.path
        endpoint_url = endpoint.url
        method = endpoint.method
        parameters = endpoint.parameters
    else:
        path = str(endpoint)
        endpoint_url = str(endpoint)

    findings = []
    matched_id = None

    # 1. Path template parameter analysis e.g. /users/{id} or /orders/{order_id}
    path_param_matches = re.findall(r"\{([a-zA-Z0-9_-]+)\}", path)
    for p_name in path_param_matches:
        if is_object_identifier_name(p_name):
            matched_id = p_name
            break

    # 2. Inspect OpenAPI declared parameters (query or path)
    if not matched_id and parameters:
        for param in parameters:
            if isinstance(param, dict):
                p_name = param.get("name", "")
                p_in = param.get("in", "")
                if p_in in ("path", "query") and is_object_identifier_name(p_name):
                    matched_id = p_name
                    break

    if matched_id:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Potential Broken Object Level Authorization",
                endpoint=endpoint_url,
                method=method,
                owasp="API1:2023 - Broken Object Level Authorization",
                description=(
                    f"This endpoint references a specific object identifier ('{matched_id}') in its route or parameters. "
                    "Ensure object-level access control policies verify that the requesting user owns or has explicit permissions for this resource."
                ),
                recommendation=(
                    "Implement authorization checks at the data/service layer to validate that the active session user has permission to access the requested resource ID."
                ),
            )
        )

    return findings