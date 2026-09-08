"""OWASP API7:2023 - Server Side Request Forgery (SSRF) Check."""

import re
from typing import Any
from scanner.models import Endpoint, Finding, Severity

SSRF_PARAM_PATTERNS = [
    r"^url$",
    r"^uri$",
    r"^.*_url$",
    r"^.*_uri$",
    r"^.*url$",
    r"^.*uri$",
    r"^link$",
    r"^target$",
    r"^destination$",
    r"^redirect.*$",
    r"^callback.*$",
    r"^webhook.*$",
    r"^feed.*$",
    r"^proxy.*$",
    r"^fetch.*$",
    r"^image_url$",
    r"^avatar_url$",
    r"^file_url$",
]

COMPILED_SSRF_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SSRF_PARAM_PATTERNS]


def _is_ssrf_param_name(name: str) -> bool:
    """Check if parameter or property name matches URL/resource loading patterns."""
    cleaned = name.strip().lower().replace("-", "_")
    return any(p.match(cleaned) for p in COMPILED_SSRF_PATTERNS)


def _extract_ssrf_properties(schema: dict[str, Any] | None) -> set[str]:
    """Inspect JSON Schema for SSRF-style property names."""
    if not isinstance(schema, dict):
        return set()

    found: set[str] = set()
    props = schema.get("properties")
    if isinstance(props, dict):
        for prop_name, prop_schema in props.items():
            if _is_ssrf_param_name(str(prop_name)):
                found.add(str(prop_name))
            if isinstance(prop_schema, dict):
                found.update(_extract_ssrf_properties(prop_schema))

    for comp_key in ("allOf", "anyOf", "oneOf"):
        comp_list = schema.get(comp_key)
        if isinstance(comp_list, list):
            for sub_schema in comp_list:
                if isinstance(sub_schema, dict):
                    found.update(_extract_ssrf_properties(sub_schema))

    return found


def check_ssrf(
    endpoint: Endpoint | str,
    method: str = "GET",
    parameters: list[dict] | None = None,
) -> list[Finding]:
    """
    Passively inspect OpenAPI parameters and request schemas to detect potential
    Server-Side Request Forgery (SSRF) input points.
    """
    if isinstance(endpoint, Endpoint):
        endpoint_url = endpoint.url
        method = endpoint.method
        parameters = endpoint.parameters
        req_schema = endpoint.request_body_schema
    else:
        endpoint_url = str(endpoint)
        req_schema = None

    matched_inputs: set[str] = set()

    # 1. Inspect query and path parameters
    if parameters:
        for param in parameters:
            if isinstance(param, dict):
                p_name = param.get("name", "")
                if _is_ssrf_param_name(p_name):
                    matched_inputs.add(p_name)

    # 2. Inspect request body schema properties
    if req_schema:
        matched_inputs.update(_extract_ssrf_properties(req_schema))

    if matched_inputs:
        inputs_str = ", ".join(sorted(matched_inputs))
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="Potential SSRF Input Risk",
                endpoint=endpoint_url,
                method=method,
                owasp="API7:2023 - Server Side Request Forgery",
                description=(
                    f"The endpoint accepts remote URL/target parameters ({inputs_str}) that may be fetched or processed server-side. "
                    "If input validation is missing, attackers could trigger internal SSRF requests against cloud metadata services (e.g. 169.254.169.254) or local internal services."
                ),
                recommendation=(
                    "Strictly validate all user-supplied URLs using an allow-list of schemes (http/https only) and permitted destination domains. "
                    "Block requests targeting loopback addresses (127.0.0.1), RFC1918 private IPs, and cloud metadata endpoints."
                ),
            )
        ]

    return []
