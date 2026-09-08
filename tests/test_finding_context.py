from scanner.models import Finding, Severity


def test_finding_has_default_method():

    finding = Finding(
        title="Test Finding",
        severity=Severity.LOW,
        description="Test description",
        endpoint="https://api.example.com/test",
        remediation="Fix the issue",
    )

    assert finding.method == "UNKNOWN"