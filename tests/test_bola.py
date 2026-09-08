from scanner.checks.bola import check_bola_risk
from scanner.models import Endpoint


def test_detects_user_id_parameter():
    findings = check_bola_risk(
        endpoint="/users/{id}",
        method="GET",
    )
    assert len(findings) == 1
    assert "Broken Object Level Authorization" in findings[0].title


def test_detects_named_id_parameter():
    findings = check_bola_risk(
        endpoint="/orders/{order_id}",
        method="GET",
    )
    assert len(findings) == 1
    assert "Broken Object Level Authorization" in findings[0].title


def test_detects_openapi_query_parameter():
    endpoint = Endpoint(
        url="http://api.example.com/account",
        method="GET",
        path="/account",
        parameters=[{"name": "account_id", "in": "query"}],
    )
    findings = check_bola_risk(endpoint)
    assert len(findings) == 1
    assert "Broken Object Level Authorization" in findings[0].title


def test_ignores_normal_endpoint():
    findings = check_bola_risk(
        endpoint="/products",
        method="GET",
    )
    assert findings == []