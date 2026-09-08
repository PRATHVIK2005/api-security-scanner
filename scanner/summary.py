from scanner.models import Finding, Severity


def count_findings_by_severity(
    findings: list[Finding],
) -> dict[Severity, int]:
    """Count findings grouped by severity."""

    counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
    }

    for finding in findings:
        counts[finding.severity] += 1

    return counts