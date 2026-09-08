"""OWASP API10:2023 - Unsafe Consumption of APIs Check."""

from scanner.models import Endpoint, Finding, Severity

THIRD_PARTY_INTEGRATION_KEYWORDS = {
    "webhook": "Inbound Webhook Consumption",
    "callback": "Third-Party Callback Processing",
    "proxy": "Outbound Content Proxying",
    "integration": "Third-Party Service Integration",
    "gateway": "Upstream API Gateway / Bridge",
    "third_party": "External Partner API",
    "sync_remote": "Remote Data Synchronization",
    "oauth_callback": "OAuth Provider Callback",
    "external_feed": "External Feed Ingestion",
}


def check_unsafe_api_consumption(
    endpoint: Endpoint | str,
    method: str = "POST",
) -> list[Finding]:
    """
    Detect endpoints that interface with or consume external APIs and webhooks,
    highlighting the need for strict response validation, TLS certificate verification,
    and safe deserialization of upstream data.
    """
    if isinstance(endpoint, Endpoint):
        endpoint_url = endpoint.url
        path = endpoint.path.lower()
        method = endpoint.method
        op_id = (endpoint.operation_id or "").lower()
        summary = (endpoint.summary or "").lower()
        description = (endpoint.description or "").lower()
        tags = " ".join([t.lower() for t in endpoint.tags])
    else:
        endpoint_url = str(endpoint)
        path = str(endpoint).lower()
        op_id = ""
        summary = ""
        description = ""
        tags = ""

    combined_text = f"{path} {op_id} {summary} {description} {tags}"
    matched_pattern = None
    matched_type = None

    for keyword, integration_type in THIRD_PARTY_INTEGRATION_KEYWORDS.items():
        if keyword in combined_text or keyword.replace("_", "") in combined_text.replace("_", "").replace("-", ""):
            matched_pattern = keyword
            matched_type = integration_type
            break

    if matched_pattern and matched_type:
        return [
            Finding(
                severity=Severity.LOW,
                title="Potential Unsafe External API Consumption",
                endpoint=endpoint_url,
                method=method,
                owasp="API10:2023 - Unsafe Consumption of APIs",
                description=(
                    f"The endpoint appears to consume or proxy data from third-party services ({matched_type} - '{matched_pattern}'). "
                    "Integrations that trust upstream API responses without schema validation, signature verification (e.g. HMAC webhook signatures), or timeout limits are vulnerable to downstream compromise."
                ),
                recommendation=(
                    "Always validate and sanitize data received from external APIs. Require cryptographic signatures for webhooks, verify TLS certificates, enforce strict timeouts, and apply schema validation."
                ),
            )
        ]

    return []
