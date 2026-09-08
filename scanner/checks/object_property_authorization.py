"""OWASP API3:2023 - Broken Object Property Level Authorization (BOPLA) Check."""

import re
from typing import Any
import httpx

from scanner.models import Endpoint, Finding, Severity

SENSITIVE_RESPONSE_PROPERTIES = {
    "password",
    "password_hash",
    "passwd",
    "secret",
    "internal",
    "private_key",
    "ssn",
    "credit_card",
    "cvv",
    "is_admin",
    "is_superuser",
    "permissions",
}

PRIVILEGED_REQUEST_PROPERTIES = {
    "role",
    "roles",
    "is_admin",
    "admin",
    "permissions",
    "is_superuser",
    "superuser",
    "verified",
    "is_verified",
    "balance",
    "credits",
    "account_type",
}


def _extract_property_names_from_schema(schema: dict[str, Any] | None) -> set[str]:
    """Recursively extract all property names defined within a JSON Schema."""
    if not isinstance(schema, dict):
        return set()

    properties: set[str] = set()

    # Direct properties
    props = schema.get("properties")
    if isinstance(props, dict):
        for prop_name, prop_schema in props.items():
            properties.add(str(prop_name).lower())
            if isinstance(prop_schema, dict):
                properties.update(_extract_property_names_from_schema(prop_schema))

    # Array items
    items = schema.get("items")
    if isinstance(items, dict):
        properties.update(_extract_property_names_from_schema(items))

    # Composition (allOf, anyOf, oneOf)
    for comp_key in ("allOf", "anyOf", "oneOf"):
        comp_list = schema.get(comp_key)
        if isinstance(comp_list, list):
            for sub_schema in comp_list:
                if isinstance(sub_schema, dict):
                    properties.update(_extract_property_names_from_schema(sub_schema))

    return properties


def check_object_property_authorization(
    endpoint: Endpoint | str,
    response: httpx.Response | None = None,
    method: str = "GET",
) -> list[Finding]:
    """
    Check for Broken Object Property Level Authorization risks:
    1. Dangerous writable privileged properties in client request schemas (Mass Assignment / Privilege Escalation).
    2. Sensitive object property exposure in response schemas or live response bodies (Excessive Data Exposure).
    """
    findings: list[Finding] = []

    if isinstance(endpoint, Endpoint):
        endpoint_url = endpoint.url
        method = endpoint.method
        req_schema = endpoint.request_body_schema
        resp_schemas = endpoint.response_schemas
    else:
        endpoint_url = str(endpoint)
        req_schema = None
        resp_schemas = None

    # 1. Inspect request schema for dangerous writable privileged properties
    if req_schema:
        req_props = _extract_property_names_from_schema(req_schema)
        dangerous_found = req_props.intersection(PRIVILEGED_REQUEST_PROPERTIES)
        if dangerous_found:
            props_str = ", ".join(sorted(dangerous_found))
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Potential Writable Privileged Property",
                    endpoint=endpoint_url,
                    method=method,
                    owasp="API3:2023 - Broken Object Property Level Authorization",
                    description=(
                        f"The request body schema allows client-controlled properties ({props_str}) that appear to control authorization roles, administrative flags, or internal state."
                    ),
                    recommendation=(
                        "Enforce strict schema allow-lists and prevent clients from directly binding privileged properties like 'role' or 'is_admin' through Mass Assignment."
                    ),
                )
            )

    # 2. Inspect response schemas for sensitive property exposure
    if resp_schemas and isinstance(resp_schemas, dict):
        for status_code, r_schema in resp_schemas.items():
            if isinstance(r_schema, dict):
                resp_props = _extract_property_names_from_schema(r_schema)
                exposed_sensitive = resp_props.intersection(SENSITIVE_RESPONSE_PROPERTIES)
                if exposed_sensitive:
                    props_str = ", ".join(sorted(exposed_sensitive))
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="Potential Sensitive Object Property Exposure",
                            endpoint=endpoint_url,
                            method=method,
                            owasp="API3:2023 - Broken Object Property Level Authorization",
                            description=(
                                f"Response schema for status {status_code} declares potentially sensitive internal fields ({props_str}) in its output structure."
                            ),
                            recommendation=(
                                "Use Data Transfer Objects (DTOs) or projection filters to filter out sensitive internal object fields before returning responses."
                            ),
                        )
                    )
                    break

    # 3. Live response inspection (if live response is provided)
    if response is not None:
        try:
            data = response.json()
            if isinstance(data, (dict, list)):
                keys_found = _extract_keys_from_json(data)
                live_sensitive = keys_found.intersection(SENSITIVE_RESPONSE_PROPERTIES)
                if live_sensitive and not any(f.title == "Potential Sensitive Object Property Exposure" for f in findings):
                    props_str = ", ".join(sorted(live_sensitive))
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="Potential Sensitive Object Property Exposure",
                            endpoint=endpoint_url,
                            method=method,
                            owasp="API3:2023 - Broken Object Property Level Authorization",
                            description=(
                                f"The live API response includes sensitive object properties ({props_str}) that may expose internal security attributes."
                            ),
                            recommendation=(
                                "Ensure responses only include public, necessary fields. Remove internal credentials, hashes, and administrative fields."
                            ),
                        )
                    )
        except Exception:
            pass

    return findings


def _extract_keys_from_json(obj: Any) -> set[str]:
    """Recursively collect dictionary key names from parsed JSON data."""
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(str(k).lower())
            keys.update(_extract_keys_from_json(v))
    elif isinstance(obj, list):
        for item in obj:
            keys.update(_extract_keys_from_json(item))
    return keys
