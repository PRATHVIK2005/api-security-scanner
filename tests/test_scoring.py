from scanner.models import Finding, Severity
from scanner.scoring import (
    calculate_security_score,
    get_risk_level,
)


def make_finding(
    severity: Severity,
    endpoint: str = "https://api.example.com",
) -> Finding:

    return Finding(
        title="Test Finding",
        severity=severity,
        description="Test description",
        endpoint=endpoint,
        remediation="Fix the issue",
    )


def test_perfect_score():

    score = calculate_security_score([])

    assert score == 100


def test_low_finding_penalty():

    findings = [
        make_finding(Severity.LOW),
    ]

    score = calculate_security_score(findings)

    assert score == 97


def test_repeated_high_findings_have_reduced_penalty():

    findings = [
        make_finding(Severity.HIGH, endpoint="https://api.example.com/1"),
        make_finding(Severity.HIGH, endpoint="https://api.example.com/2"),
    ]

    score = calculate_security_score(findings)

    # First HIGH = 15
    # Second HIGH = 6
    # Uncapped total = 21, but MAX for HIGH = 20
    # Score = 100 - 20

    assert score == 80


def test_score_never_goes_below_zero():

    findings = [
        Finding(
            title=f"Critical Finding {index}",
            severity=Severity.CRITICAL,
            description="Test",
            endpoint="https://api.example.com",
        )
        for index in range(10)
    ]

    score = calculate_security_score(findings)

    # 10 distinct CRITICAL groups × 35 cap each = 350 total penalty
    # Score clamped to 0
    assert score == 0

def test_different_finding_titles_get_full_penalties():

    findings = [
        Finding(
            title="Missing Authentication",
            severity=Severity.HIGH,
            description="Test",
            endpoint="https://api.example.com/users",
        ),
        Finding(
            title="Exposed Admin Endpoint",
            severity=Severity.HIGH,
            description="Test",
            endpoint="https://api.example.com/admin",
        ),
    ]

    score = calculate_security_score(findings)

    # 15 + 15 = 30 penalty
    assert score == 70
    
def test_repeated_low_findings_have_reduced_penalty():

    findings = [
        Finding(
            title="Missing Header",
            severity=Severity.LOW,
            description="Test",
            endpoint=f"https://api.example.com/{index}",
        )
        for index in range(3)
    ]

    score = calculate_security_score(findings)

    # First LOW = 3
    # Two additional LOW findings = 1 + 1
    # Total penalty = 5

    assert score == 95
    
    
def test_risk_levels():

    assert get_risk_level(100) == "LOW"
    assert get_risk_level(85) == "LOW"

    assert get_risk_level(84) == "MEDIUM"
    assert get_risk_level(70) == "MEDIUM"

    assert get_risk_level(69) == "HIGH"
    assert get_risk_level(40) == "HIGH"

    assert get_risk_level(39) == "CRITICAL"


def test_repeated_findings_respect_penalty_cap():

    findings = [
        Finding(
            title="Missing Security Header",
            severity=Severity.LOW,
            description="Test",
            endpoint=f"https://api.example.com/{index}",
        )
        for index in range(10)
    ]

    score = calculate_security_score(findings)

    # Maximum LOW penalty is 5
    assert score == 95


def test_different_finding_types_have_separate_caps():

    findings = [
        Finding(
            title="Missing Header",
            severity=Severity.LOW,
            description="Test",
            endpoint="https://api.example.com/one",
        ),
        Finding(
            title="Missing Rate Limiting",
            severity=Severity.MEDIUM,
            description="Test",
            endpoint="https://api.example.com/two",
        ),
    ]

    score = calculate_security_score(findings)

    # LOW = 3
    # MEDIUM = 8
    # Total = 11
    assert score == 89


def test_duplicate_identical_findings_not_penalized_twice():
    findings = [
        Finding(
            title="Missing Security Header",
            severity=Severity.LOW,
            endpoint="https://api.example.com/api",
            method="GET",
        ),
        Finding(
            title="Missing Security Header",
            severity=Severity.LOW,
            endpoint="https://api.example.com/api",
            method="GET",
        ),
    ]

    score = calculate_security_score(findings)
    # Only 1 unique finding: penalty 3 -> score 97
    assert score == 97.0


def test_string_severity_normalized():
    finding = Finding(
        title="Custom Finding",
        severity=Severity.HIGH,
        endpoint="https://api.example.com",
    )
    score = calculate_security_score([finding])
    assert score == 85.0