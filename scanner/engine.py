import httpx
import os
import time
from datetime import datetime, timezone

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
from scanner.bola_verification import load_bola_config, verify_bola_cases
from scanner.deduplication import deduplicate_findings
from scanner.discovery import discover_endpoints
from scanner.knowledge import get_finding_knowledge
from scanner.models import DiscoveryResult, ScanMode, ScanResult
from scanner.scoring import calculate_security_score, get_risk_level
from scanner.transport import create_scanner_client
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
}

# Active mode adds bounded, read-only probes. It never sends writes, even when
# an OpenAPI document advertises a body-bearing operation.
SAFE_ACTIVE_METHODS = ACTIVE_METHODS


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
    specification_url: str | None = None,
    endpoint_list: str | None = None,
    bola_config_file: str | None = None,
) -> ScanResult:
    """Run security checks against an API aligned with OWASP API Security Top 10 (2023)."""
    url = validate_target_url(url)

    if isinstance(mode, str):
        mode = ScanMode(mode.lower())

    findings = []
    unreachable_endpoints = 0
    interrupted = False

    client_headers = {}
    if headers:
        client_headers.update(headers)
    if token:
        client_headers["Authorization"] = f"Bearer {token}"

    scan_started_at = datetime.now(timezone.utc)
    try:
        max_scan_seconds = float(os.getenv("API_SCANNER_MAX_SCAN_SECONDS", "300"))
    except ValueError as exc:
        raise ValueError("API_SCANNER_MAX_SCAN_SECONDS must be numeric") from exc
    if not 1 <= max_scan_seconds <= 900:
        raise ValueError("API_SCANNER_MAX_SCAN_SECONDS must be between 1 and 900")
    scan_deadline = time.monotonic() + max_scan_seconds
    bola_config = load_bola_config(bola_config_file) if bola_config_file else None
    client = create_scanner_client(headers=client_headers, scan_deadline=scan_deadline)
    discovery_options = {"headers": client_headers, "client": client}
    if specification_url is not None:
        discovery_options["specification_url"] = specification_url
    if endpoint_list is not None:
        discovery_options["endpoint_list"] = endpoint_list
    errors: list[str] = []
    try:
        discovery = discover_endpoints(url, **discovery_options)
    except KeyboardInterrupt:
        interrupted = True
        errors.append("Scan interrupted during endpoint discovery; no operations were scanned.")
        discovery = DiscoveryResult(
            endpoints=[],
            source="Interrupted",
            limitations=["Endpoint discovery did not complete."],
        )

    allowed_methods = PASSIVE_METHODS if mode == ScanMode.PASSIVE else SAFE_ACTIVE_METHODS

    endpoints = [endpoint for endpoint in discovery.endpoints if endpoint.method in allowed_methods]

    scanner_client = client
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
            if time.monotonic() >= scan_deadline:
                errors.append("Total scan time limit reached; remaining operations were skipped.")
                break
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

        except httpx.RequestError as exc:
            unreachable_endpoints += 1
            category = (
                "resource limit" if "limit" in str(exc).lower() or "exceed" in str(exc).lower() else "request failed"
            )
            errors.append(f"{endpoint.method} endpoint: {category} ({type(exc).__name__})")
        except KeyboardInterrupt:
            interrupted = True
            errors.append("Scan interrupted by operator; remaining operations were skipped.")
            break

    if bola_config is not None:
        findings.extend(verify_bola_cases(client, url, bola_config))

    transport = getattr(scanner_client, "_scanner_transport", None)
    if transport is not None:
        failures = getattr(transport, "failures", [])
        for failure in failures if isinstance(failures, list) else []:
            summary = f"HTTP probe failed ({failure})"
            if summary not in errors:
                errors.append(summary)
    scanner_client.close()

    findings = deduplicate_findings(findings)
    security_score = calculate_security_score(findings)
    risk_level = get_risk_level(security_score)
    findings = enrich_findings(findings)

    partial = bool(errors or discovery.limitations or discovery.source == "Fallback")
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
        discovery_attempts=discovery.attempts,
        discovery_limitations=discovery.limitations,
        scan_status="interrupted" if interrupted else ("partial" if partial else "complete"),
        scan_started_at=scan_started_at,
        scan_completed_at=datetime.now(timezone.utc),
        errors=errors,
    )
