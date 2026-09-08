from scanner.models import Finding


def deduplicate_findings(
    findings: list[Finding],
) -> list[Finding]:
    """Remove duplicate security findings."""

    unique_findings = []
    seen = set()

    for finding in findings:

        key = (
            finding.title,
            finding.endpoint,
            finding.method,
        )

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return unique_findings
