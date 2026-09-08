from scanner.models import Finding, Severity
from scanner.summary import count_findings_by_severity


def make_finding(
    severity: Severity,
) -> Finding:

    return Finding(
        title="Test Finding",
        severity=severity,
        description="Test description",
        endpoint="https://api.example.com",
        remediation="Fix the issue",
    )


def test_empty_findings():

    counts = count_findings_by_severity([])

    assert counts[Severity.CRITICAL] == 0
    assert counts[Severity.HIGH] == 0
    assert counts[Severity.MEDIUM] == 0
    assert counts[Severity.LOW] == 0


def test_count_findings_by_severity():

    findings = [
        make_finding(Severity.HIGH),
        make_finding(Severity.HIGH),
        make_finding(Severity.MEDIUM),
        make_finding(Severity.LOW),
        make_finding(Severity.LOW),
        make_finding(Severity.LOW),
    ]

    counts = count_findings_by_severity(findings)

    assert counts[Severity.CRITICAL] == 0
    assert counts[Severity.HIGH] == 2
    assert counts[Severity.MEDIUM] == 1
    assert counts[Severity.LOW] == 3