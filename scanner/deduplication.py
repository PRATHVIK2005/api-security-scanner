from hashlib import sha256

from scanner.models import Finding


def deduplicate_findings(
    findings: list[Finding],
) -> list[Finding]:
    """Remove duplicate security findings."""

    unique_findings = []
    seen = set()

    for finding in findings:
        key = (
            finding.check_id,
            finding.title,
            finding.endpoint,
            finding.method,
            finding.owasp,
        )

        identity = "|".join(str(part or "") for part in key)
        finding.finding_id = sha256(identity.encode("utf-8")).hexdigest()[:16]

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return unique_findings
