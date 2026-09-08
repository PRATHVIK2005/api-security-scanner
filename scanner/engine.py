import httpx

from scanner.checks.active_rate_limiting import check_active_rate_limiting
from scanner.checks.api_versioning import check_api_versioning
from scanner.checks.authentication import check_missing_authentication
from scanner.checks.bola import check_bola_risk
from scanner.checks.business_flow import check_business_flow
from scanner.checks.cors import check_cors
from scanner.checks.exposed_endpoints import check_exposed_endpoint
from scanner.checks.http_methods import check_http_methods
from scanner.checks.information_disclosure import check_information_disclosure
from scanner.checks.misconfiguration import check_security_headers
from scanner.checks.object_property_authorization import check_object_property_authorization
from scanner.checks.rate_limiting import check_rate_limiting
from scanner.checks.sensitive_data import check_sensitive_data
from scanner.checks.ssrf import check_ssrf
from scanner.checks.token_security import check_token_security
from scanner.checks.unsafe_api_consumption import check_unsafe_api_consumption
from scanner.deduplication import deduplicate_findings
from scanner.discovery import discover_endpoints
from scanner.knowledge import get_finding_knowledge
from scanner.models import ScanMode, ScanResult
from scanner.scoring import calculate_security_score, get_risk_level
from scanner.validation import validate_target_url

PASSIVE_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
}

ACTIVE_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
    "POST",
    "PUT",
    "PATCH",
}


def add_method_to_findings(
    findings: list,
    method: str,
) -> list:
    """Attach the HTTP method to each finding."""
    for finding in findings:
        finding.method = method
    return findings


def enrich_findings(findings):
    """Add security knowledge to scanner findings."""
    for finding in findings:
        knowledge = get_finding_knowledge(finding.title)
        if not finding.owasp:
            finding.owasp = knowledge["owasp"]
        if not finding.description:
            finding.description = knowledge["description"]
        if not finding.recommendation:
            finding.recommendation = knowledge["recommendation"]
    return findings


def scan(
    url: str,
    mode: ScanMode = ScanMode.PASSIVE,
    token: str | None = None,
    headers: dict[str, str] | None = None,
) -> ScanResult:
    """Run security checks against an API aligned with OWASP API Security Top 10 (2023)."""
    url = validate_target_url(url)

    if isinstance(mode, str):
        mode = ScanMode(mode.lower())

    findings = []
    unreachable_endpoints = 0

    client_headers = {}
    if headers:
        client_headers.update(headers)
    if token:
        client_headers["Authorization"] = f"Bearer {token}"

    discovery = discover_endpoints(url, headers=client_headers)

    allowed_methods = (
        PASSIVE_METHODS
        if mode == ScanMode.PASSIVE
        else ACTIVE_METHODS
    )

    endpoints = [
        endpoint
        for endpoint in discovery.endpoints
        if endpoint.method in allowed_methods
    ]

    with httpx.Client(
        timeout=10,
        follow_redirects=True,
        headers=client_headers,
    ) as client:
        for endpoint in endpoints:
            # 1. API1: Broken Object Level Authorization (BOLA)
            findings.extend(
                add_method_to_findings(
                    check_bola_risk(endpoint, method=endpoint.method),
                    endpoint.method,
                )
            )

            # 2. API2: Broken Authentication
            findings.extend(
                add_method_to_findings(
                    check_missing_authentication(endpoint),
                    endpoint.method,
                )
            )

            # 3. API3: Broken Object Property Level Authorization (schema inspection)
            findings.extend(
                add_method_to_findings(
                    check_object_property_authorization(endpoint, method=endpoint.method),
                    endpoint.method,
                )
            )

            # 4. API6: Unrestricted Access to Sensitive Business Flows
            findings.extend(
                add_method_to_findings(
                    check_business_flow(endpoint, method=endpoint.method),
                    endpoint.method,
                )
            )

            # 5. API7: Server Side Request Forgery (SSRF)
            findings.extend(
                add_method_to_findings(
                    check_ssrf(endpoint, method=endpoint.method),
                    endpoint.method,
                )
            )

            # 6. API9: Improper Inventory Management
            findings.extend(
                add_method_to_findings(
                    check_api_versioning(endpoint, method=endpoint.method),
                    endpoint.method,
                )
            )

            # 7. API10: Unsafe Consumption of APIs
            findings.extend(
                add_method_to_findings(
                    check_unsafe_api_consumption(endpoint, method=endpoint.method),
                    endpoint.method,
                )
            )

            # Live HTTP Request Checks
            try:
                response = client.request(
                    endpoint.method,
                    endpoint.url,
                )

                # API5: Broken Function Level Authorization (Exposed Endpoints)
                findings.extend(
                    add_method_to_findings(
                        check_exposed_endpoint(
                            endpoint,
                            response.status_code,
                        ),
                        endpoint.method,
                    )
                )

                # API8: Security Misconfiguration (Headers)
                findings.extend(
                    add_method_to_findings(
                        check_security_headers(
                            endpoint.url,
                            response,
                        ),
                        endpoint.method,
                    )
                )

                # API8: Security Misconfiguration (Information Disclosure)
                findings.extend(
                    add_method_to_findings(
                        check_information_disclosure(
                            endpoint.url,
                            response,
                        ),
                        endpoint.method,
                    )
                )

                # API2 / API3: Sensitive Data in Response
                findings.extend(
                    add_method_to_findings(
                        check_sensitive_data(
                            endpoint.url,
                            response,
                        ),
                        endpoint.method,
                    )
                )

                # API2: Token Security
                findings.extend(
                    add_method_to_findings(
                        check_token_security(
                            endpoint.url,
                            response,
                        ),
                        endpoint.method,
                    )
                )

                # API3: Live Response Object Property Exposure
                findings.extend(
                    add_method_to_findings(
                        check_object_property_authorization(
                            endpoint,
                            response=response,
                            method=endpoint.method,
                        ),
                        endpoint.method,
                    )
                )

                # API8: Security Misconfiguration (CORS)
                findings.extend(
                    add_method_to_findings(
                        check_cors(
                            client,
                            endpoint.url,
                        ),
                        endpoint.method,
                    )
                )

                # API8: Security Misconfiguration (HTTP Methods)
                findings.extend(
                    add_method_to_findings(
                        check_http_methods(
                            client,
                            endpoint.url,
                        ),
                        endpoint.method,
                    )
                )

                # API4: Unrestricted Resource Consumption (Passive Rate Limiting)
                findings.extend(
                    add_method_to_findings(
                        check_rate_limiting(
                            endpoint.url,
                            response,
                        ),
                        endpoint.method,
                    )
                )

                # API4: Unrestricted Resource Consumption (Active Rate Limiting)
                if mode == ScanMode.ACTIVE:
                    findings.extend(
                        add_method_to_findings(
                            check_active_rate_limiting(
                                client,
                                endpoint.url,
                            ),
                            endpoint.method,
                        )
                    )

            except httpx.RequestError:
                unreachable_endpoints += 1

    findings = deduplicate_findings(findings)
    security_score = calculate_security_score(findings)
    risk_level = get_risk_level(security_score)
    findings = enrich_findings(findings)

    return ScanResult(
        target=url,
        endpoints_scanned=len(endpoints),
        unreachable_endpoints=unreachable_endpoints,
        findings=findings,
        discovery_source=discovery.source,
        specification_url=discovery.specification_url,
        security_score=security_score,
        risk_level=risk_level,
        scan_mode=mode.value if isinstance(mode, ScanMode) else str(mode),
    )