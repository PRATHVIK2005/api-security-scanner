from scanner.checks.api_versioning import check_api_versioning
from scanner.models import Endpoint


def test_detects_legacy_endpoint():
    findings = check_api_versioning(
        endpoint="/legacy/users",
        method="GET",
    )
    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"
    assert findings[0].title == "Potential Deprecated API Endpoint"


def test_detects_deprecated_endpoint():
    findings = check_api_versioning(
        endpoint="/deprecated/orders",
        method="GET",
    )
    assert len(findings) == 1


def test_detects_openapi_deprecated_flag():
    endpoint = Endpoint(
        url="https://api.example.com/items/old-list",
        method="GET",
        path="/items/old-list",
        deprecated=True,
    )
    findings = check_api_versioning(endpoint)
    assert len(findings) == 1
    assert findings[0].title == "Deprecated OpenAPI Operation Declared"


def test_detects_v0_api():
    findings = check_api_versioning(
        endpoint="/api/v0/users",
        method="GET",
    )
    assert len(findings) == 1
    assert findings[0].severity.value == "LOW"


def test_detects_beta_api():
    findings = check_api_versioning(
        endpoint="/v1beta/admin",
        method="GET",
    )
    assert len(findings) == 1


def test_ignores_current_api():
    findings = check_api_versioning(
        endpoint="/api/v2/users",
        method="GET",
    )
    assert findings == []