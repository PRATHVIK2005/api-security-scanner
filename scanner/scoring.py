from collections import defaultdict

from scanner.deduplication import deduplicate_findings
from scanner.models import Finding, Severity


FIRST_OCCURRENCE_PENALTIES = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}


ADDITIONAL_OCCURRENCE_PENALTIES = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}


MAX_PENALTIES = {
    Severity.CRITICAL: 35,
    Severity.HIGH: 20,
    Severity.MEDIUM: 12,
    Severity.LOW: 5,
}


def _normalize_severity(sev) -> Severity:
    if isinstance(sev, Severity):
        return sev
    try:
        return Severity(str(sev).upper())
    except (ValueError, AttributeError):
        return Severity.LOW


def calculate_security_score(
    findings: list[Finding],
) -> float:
    """Calculate a security score from 0 to 100."""
    if not findings:
        return 100.0

    unique_findings = deduplicate_findings(findings)

    grouped_findings = defaultdict(list)
    for finding in unique_findings:
        grouped_findings[finding.title].append(finding)

    total_penalty = 0

    for findings_group in grouped_findings.values():
        severity = _normalize_severity(findings_group[0].severity)

        first_penalty = FIRST_OCCURRENCE_PENALTIES.get(
            severity,
            0,
        )

        additional_penalty = (
            ADDITIONAL_OCCURRENCE_PENALTIES.get(
                severity,
                0,
            )
            * (len(findings_group) - 1)
        )

        group_penalty = (
            first_penalty
            + additional_penalty
        )

        max_penalty = MAX_PENALTIES.get(
            severity,
            group_penalty,
        )

        total_penalty += min(
            group_penalty,
            max_penalty,
        )

    score = max(
        0.0,
        min(100.0, float(100 - total_penalty)),
    )

    return float(score)


def get_risk_level(
    score: float,
) -> str:
    """Return a human-readable risk level."""

    if score >= 85:
        return "LOW"

    if score >= 70:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"