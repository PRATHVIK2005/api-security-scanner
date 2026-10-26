"""SARIF 2.1.0 reporting for API scan results."""

import json
import re
from hashlib import sha256
from urllib.parse import urlparse

from scanner.models import ScanResult
from scanner.redaction import redact_text, redact_url


def _rule_id(finding) -> str:
    value = getattr(finding, "check_id", None) or getattr(finding, "finding_id", None) or "api-security.finding"
    value = redact_text(str(value)) or "api-security.finding"
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", value)[:100]
    return safe or "api-security.finding"


def _level(severity) -> str:
    value = getattr(severity, "value", severity)
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(
        str(value).upper(), "note"
    )


def generate_sarif_report(result: ScanResult, output_path=None) -> str:
    """Return a redacted SARIF 2.1.0 document, optionally writing it to disk."""
    rules = {}
    results = []
    for finding in result.findings:
        rid = _rule_id(finding)
        rules.setdefault(
            rid,
            {
                "id": rid,
                "shortDescription": {"text": redact_text(str(getattr(finding, "title", "Finding"))) or "Finding"},
                "properties": {"tags": ["security", "api"]},
            },
        )
        endpoint = redact_url(str(getattr(finding, "endpoint", "")))
        location = None
        method = str(getattr(finding, "method", "UNKNOWN") or "UNKNOWN").upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "UNKNOWN"}:
            method = "UNKNOWN"
        severity = str(
            getattr(getattr(finding, "severity", "INFO"), "value", getattr(finding, "severity", "INFO"))
        ).upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "INFO"
        confidence = str(getattr(finding, "confidence", "low")).lower()
        if confidence not in {"low", "medium", "high"}:
            confidence = "low"
        verification_status = str(getattr(finding, "verification_status", "potential")).lower()
        if verification_status not in {
            "potential",
            "confirmed",
            "verified_negative",
            "verified_public",
            "inconclusive",
        }:
            verification_status = "potential"
        if endpoint:
            try:
                parsed = urlparse(endpoint)
                if parsed.scheme in {"http", "https"} and parsed.hostname:
                    location = {"physicalLocation": {"artifactLocation": {"uri": endpoint}}}
            except (ValueError, TypeError):
                location = None
        entry = {
            "ruleId": rid,
            "level": _level(getattr(finding, "severity", "INFO")),
            "message": {"text": redact_text(str(getattr(finding, "title", "Security finding"))) or "Security finding"},
            "partialFingerprints": {
                "apiSecurity/v1": sha256(str(getattr(finding, "finding_id", "") or rid).encode("utf-8")).hexdigest()
            },
            "properties": {
                "severity": severity,
                "confidence": confidence,
                "verificationStatus": verification_status,
                "httpMethod": method,
                "endpoint": endpoint or "",
            },
        }
        if location:
            entry["locations"] = [location]
        results.append(entry)
    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "API Security Scanner", "version": "0.1.0", "rules": list(rules.values())}},
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": result.scan_status == "complete",
                        "properties": {
                            "scanStatus": str(result.scan_status),
                            "discoverySource": redact_text(str(result.discovery_source)) or "Unknown",
                            "discoveryLimitations": [redact_text(str(item)) for item in result.discovery_limitations],
                            "errors": [redact_text(str(item)) for item in result.errors],
                        },
                    }
                ],
                "properties": {"scanStatus": str(result.scan_status), "endpointLocationsUseRequestUris": True},
            }
        ],
    }
    document = json.dumps(sarif, indent=2, ensure_ascii=False)
    if output_path is not None:
        from pathlib import Path

        Path(output_path).write_text(document, encoding="utf-8")
    return document
