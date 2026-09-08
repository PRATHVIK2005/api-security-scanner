from scanner.deduplication import deduplicate_findings
from scanner.models import Finding, Severity


def create_finding(
    title: str,
    endpoint: str,
    method: str,
) -> Finding:

    return Finding(
        title=title,
        severity=Severity.MEDIUM,
        endpoint=endpoint,
        method=method,
        description="Test finding",
    )


def test_duplicate_findings_are_removed():

    finding = create_finding(
        "Missing Authentication",
        "https://api.example.com/users",
        "GET",
    )

    findings = [
        finding,
        finding,
    ]

    result = deduplicate_findings(findings)

    assert len(result) == 1


def test_different_methods_are_not_duplicates():

    findings = [
        create_finding(
            "Missing Authentication",
            "https://api.example.com/users",
            "GET",
        ),
        create_finding(
            "Missing Authentication",
            "https://api.example.com/users",
            "POST",
        ),
    ]

    result = deduplicate_findings(findings)

    assert len(result) == 2


def test_different_titles_are_not_duplicates():

    findings = [
        create_finding(
            "Missing Authentication",
            "https://api.example.com/users",
            "GET",
        ),
        create_finding(
            "Missing Rate Limiting",
            "https://api.example.com/users",
            "GET",
        ),
    ]

    result = deduplicate_findings(findings)

    assert len(result) == 2
